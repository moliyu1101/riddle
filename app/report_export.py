"""报告模板化 + 导出增强：按 SRC 类型渲染分节结构，生成 docx/html/md/json。

- 模板化：不同 src_type（edusrc/enterprise）给出不同章节配置，前端按 sections 渲染章节导航。
- 导出：纯标准库生成 .docx（zip+xml），html 自包含可打印 PDF，md/json 复用现有逻辑。
"""
from __future__ import annotations

import re

import base64
import html as _html
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import worker_config
from app.db.models import Finding, Review, to_cst_iso
from app.schemas import Step
from app.tools.evidence_capture import render_snapshot_markdown

# 章节类型：overview 概览 / text 文本 / steps 复现 / code 代码 / evidence 证据 / chain 攻击链路 / quote 引用
_REPORT_TEMPLATES: dict[str, dict[str, Any]] = {
    "edusrc": {
        "label": "教育行业",
        "sections": [
            {"key": "overview", "label": "概览", "type": "overview"},
            {"key": "description", "label": "漏洞描述", "type": "text"},
            {"key": "scope", "label": "影响范围", "type": "text"},
            {"key": "steps", "label": "复现步骤", "type": "steps"},
            {"key": "poc", "label": "验证 PoC", "type": "code"},
            {"key": "evidence", "label": "证据链", "type": "evidence"},
            {"key": "chain", "label": "攻击链路", "type": "chain"},
            {"key": "review", "label": "审核结论", "type": "quote"},
        ],
    },
    "enterprise": {
        "label": "企业SRC",
        "sections": [
            {"key": "overview", "label": "概览", "type": "overview"},
            {"key": "description", "label": "漏洞描述", "type": "text"},
            {"key": "scope", "label": "业务影响", "type": "text"},
            {"key": "steps", "label": "复现步骤", "type": "steps"},
            {"key": "poc", "label": "验证 PoC", "type": "code"},
            {"key": "evidence", "label": "证据链", "type": "evidence"},
            {"key": "chain", "label": "攻击链路", "type": "chain"},
            {"key": "review", "label": "审核结论", "type": "quote"},
        ],
    },
}


def normalize_steps(steps: Any) -> list[dict]:
    """把复现步骤统一成 [{desc, poc, poc_http}]：兼容旧版纯字符串列表与 Step 对象。

    新版每步可以是 {desc, poc, poc_http} 对象（poc=curl 验证命令，poc_http=原始 HTTP 请求包）；
    旧版是字符串，poc 归入全局 poc。
    """
    out: list[dict] = []
    for s in steps or []:
        if isinstance(s, dict):
            desc = str(s.get("desc") or s.get("text") or s.get("description") or s.get("step") or "").strip()
            poc = str(s.get("poc") or s.get("curl") or s.get("command") or "").strip()
            poc_http = str(s.get("poc_http") or s.get("http") or s.get("request") or "").strip()
        elif isinstance(s, Step):
            desc = str(s.desc or "").strip()
            poc = str(s.poc or "").strip()
            poc_http = str(s.poc_http or "").strip()
        else:
            desc = str(s or "").strip()
            poc = ""
            poc_http = ""
        if desc:
            out.append({"desc": desc, "poc": poc, "poc_http": poc_http})
    return out


def _eff(f: Finding, r: Review | None, key: str):
    e = (r.user_edits if r else None) or {}
    v = e.get(key)
    if v is not None and v != "":
        return v
    return getattr(f, key, None)


def _sev(f: Finding, r: Review | None) -> str:
    return (r.user_severity or r.severity_final or f.severity_claimed or "-") if r else (f.severity_claimed or "-")


def _conf(r: Review | None) -> str:
    return r.confidence if r else "-"


def _owner(f: Finding) -> str:
    # edu_school 是 API 层派生字段（模型无此列），端点调用前会补到对象上；未补时兜底 owner。
    return (getattr(f, "edu_school", "") or "").strip() or f.owner or "-"


def _evidence_items(f: Finding) -> list[dict]:
    ev = f.evidence or {}
    if not isinstance(ev, dict):
        ev = ev.model_dump() if hasattr(ev, "model_dump") else {}
    items = []
    if f.raw_request:
        items.append({"label": "原始请求", "kind": "code", "content": f.raw_request})
    if f.raw_response:
        items.append({"label": "原始响应", "kind": "code", "content": f.raw_response})
    if ev.get("extracted_data_sample"):
        items.append({"label": "数据样本", "kind": "code", "content": ev["extracted_data_sample"]})
    if ev.get("tool_output"):
        items.append({"label": "工具输出", "kind": "code", "content": ev["tool_output"]})
    if ev.get("notes"):
        items.append({"label": "说明", "kind": "text", "content": ev["notes"]})
    snap = ev.get("snapshot")
    if snap:
        item = {"label": "存证快照", "kind": "snapshot", "content": render_snapshot_markdown(snap)}
        shot = snap.get("screenshot") if isinstance(snap, dict) else None
        if isinstance(shot, dict) and shot.get("ref"):
            item["screenshot_ref"] = shot["ref"]
        items.append(item)
    return items


def _screenshot_path(f: Finding, ref: str) -> Path | None:
    """按截图相对引用（evidence/screenshots/xxx.png）解析绝对路径，不存在返回 None。

    优先用存证时记录的 work_dir 目录名（executor 按 target 生成，可靠）；
    旧快照未记录时回退到 target_url 推导的 safe_name。
    """
    if not ref:
        return None
    dir_name = ""
    ev = f.evidence or {}
    if not isinstance(ev, dict):
        try:
            ev = ev.model_dump()
        except Exception:
            ev = {}
    snap = ev.get("snapshot")
    if isinstance(snap, dict):
        shot = snap.get("screenshot")
        if isinstance(shot, dict):
            dir_name = str(shot.get("workdir") or "").strip()
    if not dir_name:
        dir_name = "".join(c if c.isalnum() else "_" for c in (f.target_url or ""))[:60]
    p = Path(worker_config.work_root) / dir_name / ref
    return p if p.exists() else None


def _png_size(data: bytes) -> tuple[int, int]:
    """从 PNG 二进制解析宽高（IHDR chunk），失败返回 (0, 0)。"""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return 0, 0
    try:
        w = int.from_bytes(data[16:20], "big")
        h = int.from_bytes(data[20:24], "big")
        return w, h
    except Exception:
        return 0, 0


def _screenshot_base64(p: Path) -> str:
    try:
        return base64.b64encode(p.read_bytes()).decode()
    except Exception:
        return ""




def _docx_image_para(path: Path, r_id: str, max_width_px: int = 560) -> str:
    _docx_image_para.img_seq += 1  # OOXML docPr id must be unique across the document
    """生成 docx 内联图片段落 XML（OOXML drawing）。按 PNG 实际尺寸等比缩放。"""
    _docx_image_para.img_seq += 1  # OOXML 要求文档内 docPr id 唯一，多截图自增
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    w, h = _png_size(data)
    if w <= 0 or h <= 0:
        return ""
    scale = min(1.0, max_width_px / w)
    cx = int(w * scale * 9525)  # 1px @96dpi = 9525 EMU
    cy = int(h * scale * 9525)
    return (
        f'<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
        f'<wp:extent cx="{cx}" cy="{cy}"/>'
        f'<wp:docPr id="{_docx_image_para.img_seq}" name="screenshot.png"/>'
        f'<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:pic><pic:nvPicPr><pic:cNvPr id="{_docx_image_para.img_seq}" name="screenshot.png"/><pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{r_id}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        f'</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
    )


def _chain(f: Finding) -> list[dict]:
    return [s for s in (f.kill_chain or []) if s and s.get("method")]


_SEV_IMPACT = {"严重": 9.5, "高危": 8.0, "中危": 5.5, "低危": 3.0}


def score_breakdown(f: Finding, r: Review | None) -> dict | None:
    """风险评分分解：危害 / 利用难度 / 影响面 / 可复现性 四项（0-10），均值即总分。

    纯推导（不新增存储）：等级→危害，PoC/复现→利用难度，范围/样本→影响面，
    请求响应/步骤→可复现性。作为报告数据的组成部分，模板与导出统一携带，
    与前端作战台评分分解口径一致。
    """
    if not r:
        return None
    sev = r.user_severity or r.severity_final or f.severity_claimed or ""
    impact = _SEV_IMPACT.get(sev, 5.0)
    exploit = 5.0
    if r.reproduced:
        exploit += 1.5
    if (f.poc or "").strip():
        exploit += 1.5
    if (f.raw_request or "").strip():
        exploit += 1.0
    exploit = round(min(10.0, exploit), 1)
    scope = 5.0
    if r.in_scope:
        scope += 2.0
    if (f.affected_scope or "").strip():
        scope += 2.0
    if (f.evidence or {}).get("extracted_data_sample"):
        scope += 1.0
    scope = round(min(10.0, scope), 1)
    repro = 4.0
    if r.reproduced:
        repro += 2.5
    if (f.raw_request or "").strip() and (f.raw_response or "").strip():
        repro += 2.0
    if (f.steps or []):
        repro += 1.5
    repro = round(min(10.0, repro), 1)
    return {
        "impact": impact,
        "exploitability": exploit,
        "scope": scope,
        "reproducibility": repro,
        "total": round((impact + exploit + scope + repro) / 4, 1),
    }


_SCORE_LABELS = (
    ("impact", "危害"),
    ("exploitability", "利用难度"),
    ("scope", "影响面"),
    ("reproducibility", "可复现性"),
)


def build_report_sections(f: Finding, r: Review | None, src_type: str = "edusrc") -> dict:
    """按模板返回分节数据，前端据此渲染章节导航与正文。"""
    template = _REPORT_TEMPLATES.get((src_type or "edusrc").strip() or "edusrc", _REPORT_TEMPLATES["edusrc"])
    data = {
        "overview": {
            "title": _eff(f, r, "title") or f.title,
            "vuln_type": f.vuln_type,
            "target_url": f.target_url,
            "owner": _owner(f),
            "severity": _sev(f, r),
            "confidence": _conf(r),
            "score": r.score if r else None,
            "score_breakdown": score_breakdown(f, r),
            "created_at": to_cst_iso(f.created_at),
            "llm_model": getattr(f, "llm_model", "") or "",
            "steps_count": len(normalize_steps(_eff(f, r, "steps"))),
            "chain_count": len(_chain(f)),
        },
        "description": _eff(f, r, "description") or "",
        "scope": _eff(f, r, "affected_scope") or "",
        "steps": normalize_steps(_eff(f, r, "steps")),
        "poc": _eff(f, r, "poc") or "",
        "poc_http": _eff(f, r, "poc_http") or "",
        "evidence": _evidence_items(f),
        "chain": _chain(f),
        "review": (r.reviewer_notes if r else "") or "",
        "user_notes": (r.user_notes if r else "") or "",
    }
    return {"template": template, "data": data}


def _md_escape(text: str) -> str:
    return str(text or "").replace("|", "\\|")


def build_report_markdown(f: Finding, r: Review | None, src_type: str = "edusrc") -> str:
    """按模板渲染 Markdown（与前端 report.js 口径一致，供导出用）。"""
    sec = build_report_sections(f, r, src_type)
    d = sec["data"]
    ov = d["overview"]
    lines = [
        f"# {ov['title']}",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| **漏洞等级** | {_md_escape(ov['severity'])}（{ov['score'] or '-'} / 10） |",
        f"| **信度** | {_md_escape(ov['confidence'])} |",
        f"| **漏洞类型** | `{_md_escape(ov['vuln_type'])}` |",
        f"| **归属单位** | {_md_escape(ov['owner'])} |",
        f"| **目标 URL** | {_md_escape(ov['target_url'])} |",
    ]
    sb = ov.get("score_breakdown")
    if sb:
        lines += [
            "",
            "## 风险评分分解",
            "",
            "| 维度 | 得分 |",
            "| --- | --- |",
        ]
        lines += [f"| {label} | {sb[key]:.1f} / 10 |" for key, label in _SCORE_LABELS]
        lines.append(f"| **综合** | **{sb['total']:.1f} / 10** |")
    lines += ["",
        "## 漏洞描述",
        "",
        d["description"] or "-",
        "",
        "## 影响范围",
        "",
        d["scope"] or "-",
        "",
        "## 复现步骤",
        "",
    ]
    steps = d["steps"]
    if steps:
        for i, st in enumerate(steps, 1):
            lines.append(f"{i}. **{st['desc']}**")
            if st["poc"]:
                lines.append("")
                lines += _fence(st["poc"], "bash", indent="   ")
            if st["poc_http"]:
                lines.append("")
                lines.append("   **请求包（yakit / Burp）**")
                lines.append("")
                lines += _fence(st["poc_http"], "http", indent="   ")
            lines.append("")
    else:
        lines.append("-")
    lines += ["## 验证 PoC", "", "**curl 命令**", ""]
    lines += _fence(d["poc"] or "-", "bash")
    if d["poc_http"]:
        lines += ["", "**原始请求包（yakit / Burp 可直接导入）**", ""]
        lines += _fence(d["poc_http"], "http")
    lines += ["", "## 证据链", ""]
    for item in d["evidence"]:
        lines.append(f"**{item['label']}**")
        lines.append("")
        if item["kind"] in ("code", "snapshot"):
            lines += _fence(item["content"])
        else:
            lines.append(item["content"])
        if item.get("screenshot_ref"):
            p = _screenshot_path(f, item["screenshot_ref"])
            if p:
                b64 = _screenshot_base64(p)
                if b64:
                    lines.append("")
                    lines.append(f"![真实浏览器截图](data:image/png;base64,{b64})")
        lines.append("")
    chain = d["chain"]
    if chain:
        lines.append("## 攻击链路")
        lines.append("")
        lines.append("`" + " → ".join(s["method"] for s in chain) + "`")
        lines.append("")
        for i, s in enumerate(chain, 1):
            lines.append(f"{i}. **{s['method']}**" + (f" — {s.get('detail', '')}" if s.get("detail") else ""))
        lines.append("")
    lines.append("## AI 审核结论")
    lines.append("")
    lines.append(f"> {d['review'] or '-'}")
    if d["user_notes"]:
        lines += ["", "## 人工复审备注", "", d["user_notes"]]
    return "\n".join(lines)


def _fence(content: str, lang: str = "", indent: str = "") -> list[str]:
    """生成 markdown 代码围栏：内容含 ``` 时自动加长围栏，防止提前闭合击穿。"""
    fences = re.findall(r"^(`{3,})", content or "", re.M)
    fence = "`" * (max((len(f) for f in fences), default=2) + 1)
    head = f"{indent}{fence}{lang}"
    return [head, (content or ""), f"{indent}{fence}"]


_XML_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")




def _xml_escape(text: str) -> str:
    # XML 1.0 禁止大部分控制字符：raw_request/raw_response 抓的是任意站点响应，
    # 含二进制字节时 document.xml 非法、Word 直接拒开。
    return _XML_CTRL_RE.sub("", str(text or "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
def build_docx_bytes(f: Finding, r: Review | None, src_type: str = "edusrc") -> bytes:
    """纯标准库生成最小 .docx（zip + word/document.xml），零第三方依赖。"""
    sec = build_report_sections(f, r, src_type)
    d = sec["data"]
    ov = d["overview"]

    def para(text: str, style: str = "Normal", bold: bool = False, size: str = "22") -> str:
        text = _xml_escape(text)
        rpr = f"<w:rPr><w:b/></w:rPr>" if bold else ""
        return (
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/>'
            f'<w:rPr><w:sz w:val="{size}"/></w:rPr></w:pPr>'
            f'<w:r>{rpr}<w:t xml:space="preserve">{text}</w:t></w:r></w:p>'
        )

    def heading(text: str, level: int = 1) -> str:
        return para(text, style=f"Heading{level}", bold=True, size="28" if level == 1 else "24")

    def code(text: str) -> str:
        return f'<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr><w:r><w:t xml:space="preserve">{_xml_escape(text)}</w:t></w:r></w:p>'

    body = [heading(ov["title"], 1)]
    body.append(para(f"漏洞等级：{ov['severity']}（{ov['score'] or '-'} / 10）"))
    body.append(para(f"信度：{ov['confidence']}"))
    body.append(para(f"漏洞类型：{ov['vuln_type']}"))
    body.append(para(f"归属单位：{ov['owner']}"))
    body.append(para(f"目标 URL：{ov['target_url']}"))
    body.append(para(f"发现时间：{ov['created_at'] or '-'}"))
    sb = ov.get("score_breakdown")
    if sb:
        body.append(para(""))
        body.append(heading("风险评分分解", 2))
        for key, label in _SCORE_LABELS:
            body.append(para(f"{label}：{sb[key]} / 10"))
        body.append(para(f"综合：{sb['total']} / 10"))
    body.append(para(""))
    body.append(heading("漏洞描述", 2))
    body.append(para(d["description"] or "-"))
    body.append(heading("影响范围", 2))
    body.append(para(d["scope"] or "-"))
    body.append(heading("复现步骤", 2))
    for i, st in enumerate(d["steps"], 1):
        body.append(para(f"{i}. {st['desc']}"))
        if st["poc"]:
            body.append(code(st["poc"]))
        if st["poc_http"]:
            body.append(code(st["poc_http"]))
    if not d["steps"]:
        body.append(para("-"))
    body.append(heading("验证 PoC", 2))
    body.append(para("curl 命令", bold=True))
    body.append(code(d["poc"] or "-"))
    if d["poc_http"]:
        body.append(para("原始请求包（yakit / Burp 可直接导入）", bold=True))
        body.append(code(d["poc_http"]))
    body.append(heading("证据链", 2))
    media: list[tuple[str, bytes]] = []
    rel_entries: list[tuple[str, str]] = []
    for item in d["evidence"]:
        body.append(para(item["label"], bold=True))
        body.append(code(item["content"]) if item["kind"] in ("code", "snapshot") else para(item["content"]))
        if item.get("screenshot_ref"):
            p = _screenshot_path(f, item["screenshot_ref"])
            if p and p.exists():
                idx = len(media) + 1
                rid = f"rId{idx + 1}"
                media.append((f"image{idx}.png", p.read_bytes()))
                rel_entries.append((rid, f"media/image{idx}.png"))
                img_para = _docx_image_para(p, rid)
                if img_para:
                    body.append(img_para)
    if d["chain"]:
        body.append(heading("攻击链路", 2))
        body.append(para(" → ".join(s["method"] for s in d["chain"])))
        for i, s in enumerate(d["chain"], 1):
            body.append(para(f"{i}. {s['method']}" + (f" — {s.get('detail', '')}" if s.get("detail") else "")))
    body.append(heading("AI 审核结论", 2))
    body.append(para(d["review"] or "-"))
    if d["user_notes"]:
        body.append(heading("人工复审备注", 2))
        body.append(para(d["user_notes"]))

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
        ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
        ' xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<w:body>" + "".join(body) + "</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    document_rels = ""
    if rel_entries:
        document_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            + "".join(
                f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{target}"/>'
                for rid, target in rel_entries
            )
            + "</Relationships>"
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
        if media:
            zf.writestr("word/_rels/document.xml.rels", document_rels)
            for name, data in media:
                zf.writestr(f"word/media/{name}", data)
    return buf.getvalue()


def build_report_html(f: Finding, r: Review | None, src_type: str = "edusrc") -> str:
    """自包含 HTML 报告（浏览器可打印为 PDF）。"""
    sec = build_report_sections(f, r, src_type)
    d = sec["data"]
    ov = d["overview"]

    def esc(text: str) -> str:
        return _html.escape(str(text or ""))

    parts = [f"<h1>{esc(ov['title'])}</h1>"]
    parts.append(
        "<table class='meta'><tr><th>漏洞等级</th><td>{}</td><th>信度</th><td>{}</td></tr>"
        "<tr><th>漏洞类型</th><td>{}</td><th>归属单位</th><td>{}</td></tr>"
        "<tr><th>目标 URL</th><td>{}</td><th>发现时间</th><td>{}</td></tr></table>".format(
            esc(ov["severity"]), esc(ov["confidence"]), esc(ov["vuln_type"]),
            esc(ov["owner"]), esc(ov["target_url"]), esc(ov["created_at"] or "-"),
        )
    )
    sb = ov.get("score_breakdown")
    if sb:
        rows = "".join(
            f"<tr><td>{esc(label)}</td><td>{sb[key]} / 10</td></tr>" for key, label in _SCORE_LABELS
        )
        rows += f"<tr><td><b>综合</b></td><td><b>{sb['total']} / 10</b></td></tr>"
        parts.append(f"<h2>风险评分分解</h2><table class='meta'>{rows}</table>")
    parts.append(f"<h2>漏洞描述</h2><p>{esc(d['description'] or '-')}</p>")
    parts.append(f"<h2>影响范围</h2><p>{esc(d['scope'] or '-')}</p>")
    parts.append("<h2>复现步骤</h2><ol>")
    for i, st in enumerate(d["steps"], 1):
        item = f"<li>{esc(st['desc'])}"
        if st["poc"]:
            item += f"<pre>{esc(st['poc'])}</pre>"
        if st["poc_http"]:
            item += f"<p class='poc-tag'>请求包（yakit / Burp）</p><pre>{esc(st['poc_http'])}</pre>"
        parts.append(item + "</li>")
    parts.append("</ol>")
    parts.append(f"<h2>验证 PoC</h2><pre>{esc(d['poc'] or '-')}</pre>")
    if d["poc_http"]:
        parts.append("<p class='poc-tag'>原始请求包（yakit / Burp 可直接导入）</p>")
        parts.append(f"<pre>{esc(d['poc_http'])}</pre>")
    if d["evidence"]:
        parts.append("<h2>证据链</h2>")
        for item in d["evidence"]:
            parts.append(f"<h3>{esc(item['label'])}</h3>")
            parts.append(f"<pre>{esc(item['content'])}</pre>" if item["kind"] in ("code", "snapshot") else f"<p>{esc(item['content'])}</p>")
            if item.get("screenshot_ref"):
                p = _screenshot_path(f, item["screenshot_ref"])
                if p:
                    b64 = _screenshot_base64(p)
                    if b64:
                        parts.append(f"<img class='snap-shot' src='data:image/png;base64,{b64}' alt='真实浏览器截图' />")
    if d["chain"]:
        parts.append("<h2>攻击链路</h2><p>" + " → ".join(esc(s["method"]) for s in d["chain"]) + "</p>")
        parts.append("<ol>" + "".join(f"<li><b>{esc(s['method'])}</b> {esc(s.get('detail', ''))}</li>" for s in d["chain"]) + "</ol>")
    parts.append(f"<h2>AI 审核结论</h2><blockquote>{esc(d['review'] or '-')}</blockquote>")
    if d["user_notes"]:
        parts.append(f"<h2>人工复审备注</h2><p>{esc(d['user_notes'])}</p>")
    return (
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'>"
        "<title>{}</title><style>"
        "body{{font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;max-width:820px;margin:32px auto;padding:0 20px;color:#1f2937;line-height:1.7}}"
        "h1{{font-size:24px;border-bottom:3px solid #3b9eff;padding-bottom:10px}}"
        "h2{{font-size:18px;margin-top:28px;border-left:4px solid #3b9eff;padding-left:10px}}"
        "h3{{font-size:15px;color:#374151}}"
        "table.meta{{width:100%;border-collapse:collapse;margin:16px 0}}"
        "table.meta th,table.meta td{{border:1px solid #e5e7eb;padding:8px 10px;font-size:13px;text-align:left}}"
        "table.meta th{{background:#f3f4f6;width:90px}}"
        "pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow-x:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-all}}"
        "blockquote{{border-left:4px solid #f59e0b;background:#fffbeb;padding:10px 14px;margin:12px 0;color:#78350f}}"
        "p.poc-tag{{font-size:12px;color:#3b9eff;margin:10px 0 2px;font-weight:600}}"
        "img.snap-shot{{max-width:100%;border:1px solid #e5e7eb;border-radius:8px;margin:10px 0}}"
        "ol{{padding-left:22px}}li{{margin:4px 0}}"
        "@media print{{body{{margin:0}}pre{{white-space:pre-wrap}}}}</style></head><body>{}</body></html>"
    ).format(esc(ov["title"]), "".join(parts))

# ============ EduSRC 平台提交 JSON（原前端 buildEdusrcReportJson，收敛到后端单源） ============
_EDUSRC_CATEGORY_MAP = {
    "SQL注入漏洞": 1, "文件上传漏洞": 2, "代码执行漏洞": 3, "命令执行漏洞": 4,
    "XSS漏洞": 5, "CSRF漏洞": 6, "SSRF漏洞": 7, "点击劫持漏洞": 8,
    "弱口令": 9, "敏感信息泄露": 10, "其他漏洞": 13, "任意文件读取": 14,
    "任意文件下载": 15, "未授权访问": 16, "逻辑缺陷": 17,
    "疑似被黑/存在后门": 18, "AI漏洞": 19,
}
_EDUSRC_LEVEL_MAP = {"严重": "grave", "高危": "high", "中危": "medium", "低危": "low"}


def _edusrc_infer_category(f) -> str:
    """分类推断：具体词在前（「模板注入」「反序列化」先于泛化的「注入」），
    裸短词收紧（code/data/rce 易命中 VerificationCode/说明文字/encode）。"""
    text = f"{f.vuln_type or ''} {(f.title or '')}".lower()
    rules = (
        (r"sql|sqli", "SQL注入漏洞"),
        (r"模板注入|ssti|template.inject", "代码执行漏洞"),
        (r"反序列化|deserializ|jndi|rce|远程代码执行|命令执行|cmd|command.exec", "命令执行漏洞"),
        (r"代码执行|代码注入|code.exec", "代码执行漏洞"),
        (r"文件上传|upload.*(shell|bypass)|上传绕过", "文件上传漏洞"),
        (r"xss|跨站", "XSS漏洞"),
        (r"csrf", "CSRF漏洞"),
        (r"ssrf", "SSRF漏洞"),
        (r"clickjacking|点击劫持", "点击劫持漏洞"),
        (r"弱口令|默认口令|weak.?password|credential", "弱口令"),
        (r"任意文件下载|download.*(任意|未授权)", "任意文件下载"),
        (r"任意文件读取|路径穿越|traversal|lfi", "任意文件读取"),
        (r"逻辑缺陷|支付|订单.*篡改|验证码绕过|垂直越权|水平越权|业务逻辑", "逻辑缺陷"),
        (r"未授权访问|未鉴权|未授权", "未授权访问"),
        (r"敏感信息泄露|信息泄露|数据泄露|leak|源码泄露|备份文件", "敏感信息泄露"),
        (r"ai|prompt.inject|llm", "AI漏洞"),
    )
    for pattern, name in rules:
        if re.search(pattern, text):
            return name
    return "其他漏洞"


def _edusrc_slug(value) -> str:
    s = re.sub(r"[^a-z0-9一-鿿]+", "-", str(value or "").strip().lower())
    return s.strip("-") or "target"


def _edusrc_short_hash(value) -> str:
    h = 2166136261
    for ch in str(value or ""):
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return format(h, "08x")


def build_edusrc_report_json(f: Finding, r: Review | None, content_md: str) -> dict:
    """EduSRC 平台提交格式（含用户编辑覆盖与等级/分类推断）。"""
    edits = (r.user_edits if r else None) or {}

    def eff(key, default=""):
        v = edits.get(key)
        if v is not None and v != "":
            return v
        return getattr(f, key, None) or default

    def first_number(values, fallback):
        for v in values:
            try:
                n = int(v)
            except (TypeError, ValueError):
                continue
            if n > 0:
                return n
        return fallback

    review_sev = (r.user_severity if r else None) or (r.severity_final if r else None) or "-"
    edu_school = (getattr(f, "edu_school", "") or "").strip()
    owner = (edu_school or f.owner or str(edits.get("owner") or "")).strip()
    firm_name = owner if owner and owner != "-" else "待填写单位"
    # 标题保留用户编辑的漏洞标题（EduSRC 侧展示单位信息靠 firm_name 字段），
    # 此前 title 被整体替换为单位名，用户改过的标题被静默丢弃。
    title = str(eff("title")).strip() or (firm_name if firm_name != "待填写单位" else "知蠹 Riddle 漏洞报告")
    edusrc_meta = (f.evidence or {}).get("edusrc") if isinstance(f.evidence, dict) else {}
    edusrc_meta = edusrc_meta or {}
    category_name = _edusrc_infer_category(f)
    return {
        "id": f"riddle-{_edusrc_slug(f.vuln_type)}-{_edusrc_short_hash(f'{f.id or ""}|{f.target_url or ""}|{title}')}",
        "vuln_type": f.vuln_type or "custom",
        "title": title,
        "category": _EDUSRC_CATEGORY_MAP.get(category_name, _EDUSRC_CATEGORY_MAP["未授权访问"]),
        "level": _EDUSRC_LEVEL_MAP.get(review_sev, "medium"),
        "firm_id": first_number([edits.get("firm_id"), edusrc_meta.get("firm_id"), getattr(f, "firm_id", None)], 0),
        "firm_name": firm_name,
        "company_id": first_number([edits.get("company_id"), edusrc_meta.get("company_id"), getattr(f, "company_id", None)], 3),
        "credentials": "False",
        "url": f.target_url or "",
        "content": content_md,
    }
