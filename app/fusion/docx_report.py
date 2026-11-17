"""公文级 Word 报告：纯标准库手写 OOXML，零新增依赖。

在 Riddle 现有 ``report_export.build_docx_bytes``（正文型 docx）之上补齐
交付物质感：封面 / 目录域 / 页眉页脚页码 / 严重度着色 / 目标达成情况 /
复测记录 / 四类流量证据 / 修复路线图 / 项目符号编号部件。

本模块只消费结构化 dict，不直接读数据库，便于离线单测与复用。
"""
from __future__ import annotations

import io
import zipfile
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from app.fusion import evidence_gate, traffic_ledger

_SEVERITY_COLOR = {"critical": "C00000", "high": "E36C09", "medium": "BF9000", "low": "2F5496",
                   "严重": "C00000", "高危": "E36C09", "中危": "BF9000", "低危": "2F5496"}
_ROLE_LABEL = {"baseline": "基线请求", "proof": "利用证明", "verification": "复测验证", "supporting": "辅助证据"}


def _t(value: Any, limit: int = 8000) -> str:
    return str(value if value is not None else "").strip()[:limit]


def _steps(raw: Any) -> list[dict]:
    out: list[dict] = []
    for st in raw or []:
        if isinstance(st, dict):
            out.append({"desc": _t(st.get("desc")), "poc": _t(st.get("poc")), "poc_http": _t(st.get("poc_http"))})
        elif isinstance(st, str) and st.strip():
            out.append({"desc": _t(st), "poc": "", "poc_http": ""})
    return out


def build_report_model(finding: dict, review: dict | None = None, goals_eval: dict | None = None,
                      traffic: list[dict] | None = None, meta: dict | None = None) -> dict:
    """把各模块的数据收敛成报告模型；缺数据用占位，不抛异常。"""
    meta = meta or {}
    sev = _t(finding.get("severity_claimed") or finding.get("severity") or "").lower()
    level = evidence_gate.impact_level(finding)
    grouped = {"baseline": [], "proof": [], "verification": [], "supporting": []}
    for row in traffic or []:
        role = _t(row.get("role") or "supporting")
        grouped.setdefault(role, []).append(row)
    vuln_type = _t(finding.get("vuln_type") or "通用漏洞")
    return {
        "title": _t(finding.get("title") or "漏洞报告"),
        "subtitle": _t(meta.get("subtitle") or "安全测试报告"),
        "org": _t(meta.get("org") or "—"),
        "date": _t(meta.get("date") or datetime.now().strftime("%Y-%m-%d")),
        "classification": _t(meta.get("classification") or "内部资料 · 仅限授权范围使用"),
        "severity": sev,
        "severity_color": _SEVERITY_COLOR.get(sev, "404040"),
        "impact_level": level,
        "impact_label": evidence_gate.LEVEL_LABEL.get(level, ""),
        "vuln_type": vuln_type,
        "owner": _t(finding.get("owner") or "—"),
        "target_url": _t(finding.get("target_url") or "—"),
        "description": _t(finding.get("description") or finding.get("affected_scope") or "—"),
        "scope": _t(finding.get("affected_scope") or "—"),
        "steps": _steps(finding.get("steps")),
        "poc": _t(finding.get("poc") or ""),
        "poc_http": _t(finding.get("poc_http") or ""),
        "evidence": finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {},
        "review": {
            "verdict": _t((review or {}).get("verdict") or "待复审"),
            "severity_final": _t((review or {}).get("severity_final") or ""),
            "notes": _t((review or {}).get("reviewer_notes") or (review or {}).get("user_notes") or "—"),
            "reproduced": bool((review or {}).get("reproduced")),
        },
        "goals": goals_eval or {},
        "traffic": grouped,
        "roadmap": [
            f"针对 {vuln_type} 复核服务端输入校验与鉴权链路，确认同类接口是否共用同一缺陷。",
            "在授权范围内做回归复测，保留本次原始请求包与响应作为对照基线。",
            "按最小权限原则收敛可匿名访问的接口与数据字段，补齐访问审计日志。",
            "修复后重新执行本报告「复现步骤」，确认原 PoC 不再产生同等危害。",
        ],
    }


def _para(text: str, *, style: str = "Normal", bold: bool = False, size: int = 22,
          color: str = "", bullet: bool = False) -> str:
    rpr = "<w:rPr>" + ("<w:b/>" if bold else "") + (f'<w:color w:val="{color}"/>' if color else "") + f'<w:sz w:val="{size}"/></w:rPr>'
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/>'
    if bullet:
        ppr += '<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>'
    ppr += "</w:pPr>"
    return f'<w:p>{ppr}<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def _heading(text: str, level: int = 1) -> str:
    return _para(text, style=f"Heading{level}", bold=True, size=30 if level == 1 else 25, color="1F3864")


def _code(text: str) -> str:
    out = []
    for line in _t(text, 12000).splitlines() or [""]:
        out.append(_para(line, style="Code", size=18))
    return "".join(out)


def _table(rows: list[tuple[str, str]]) -> str:
    cell = lambda t, w=2200: (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/></w:tcPr>'
                              f'<w:p><w:r><w:t xml:space="preserve">{escape(t)}</w:t></w:r></w:p></w:tc>')
    body = "".join(f"<w:tr>{cell(k)}{cell(v, 6000)}</w:tr>" for k, v in rows)
    return (f'<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>'
            f'<w:tblBorders><w:top w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/>'
            f'<w:left w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/>'
            f'<w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr>'
            f'{body}</w:tbl>')


def render_document_xml(model: dict) -> str:
    body: list[str] = []
    # 封面
    body.append(_para(model["subtitle"], bold=True, size=40, color="1F3864"))
    body.append(_para(model["title"], bold=True, size=34, color=model["severity_color"]))
    body.append(_para(""))
    body.append(_table([
        ("报告单位", model["org"]), ("报告日期", model["date"]),
        ("密级", model["classification"]),
        ("严重度", f'{model["severity"] or "待定"}（{model["impact_level"]} {model["impact_label"]}）'),
    ]))
    body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
    # 目录域
    body.append(_heading("目录", 1))
    body.append('<w:p><w:fldSimple w:instr="TOC \\o &quot;1-2&quot; \\h \\z \\u">'
                '<w:r><w:t>打开文档时更新目录</w:t></w:r></w:fldSimple></w:p>')
    body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
    # 摘要与目标达成
    body.append(_heading("一、执行摘要", 1))
    body.append(_para(f'本报告记录 {model["vuln_type"]} 类漏洞的验证过程与证据链。', size=22))
    body.append(_para(f'影响层级：{model["impact_level"]}（{model["impact_label"]}）。', color=model["severity_color"]))
    body.append(_heading("二、目标达成情况", 1))
    goals = model.get("goals") or {}
    body.append(_para(goals.get("summary") or "本任务未设置目标（诚实终态：incomplete）。"))
    for g in (goals.get("met") or [])[:20]:
        body.append(_para(f'已达成 · {_t(g.get("title"))}｜{_t(g.get("criteria"))}', bullet=True))
    for g in (goals.get("unmet") or [])[:20]:
        body.append(_para(f'未达成 · {_t(g.get("title"))}｜{_t(g.get("reason"))}', bullet=True))
    # 漏洞详情
    body.append(_heading("三、漏洞详情", 1))
    body.append(_table([
        ("漏洞标题", model["title"]), ("漏洞类型", model["vuln_type"]),
        ("归属单位", model["owner"]), ("目标 URL", model["target_url"]),
        ("审核结论", model["review"]["verdict"]),
    ]))
    body.append(_heading("3.1 漏洞描述", 2))
    body.append(_para(model["description"]))
    body.append(_heading("3.2 影响范围", 2))
    body.append(_para(model["scope"]))
    # 复现步骤
    body.append(_heading("四、复现步骤与 PoC", 1))
    if model["steps"]:
        for i, st in enumerate(model["steps"], 1):
            body.append(_para(f'{i}. {st["desc"]}'))
            if st["poc"]:
                body.append(_code(st["poc"]))
            if st["poc_http"]:
                body.append(_code(st["poc_http"]))
    else:
        body.append(_para(model["poc"] or "（无分步 PoC）"))
        if model["poc_http"]:
            body.append(_code(model["poc_http"]))
    body.append(_heading("4.1 可执行验证命令", 2))
    body.append(_code(model["poc"] or "（未提供）"))
    # 流量证据
    body.append(_heading("五、流量证据链", 1))
    any_traffic = False
    for role in traffic_ledger.ROLES:
        rows = (model.get("traffic") or {}).get(role) or []
        if not rows:
            continue
        any_traffic = True
        body.append(_heading(f'5.{traffic_ledger.ROLES.index(role) + 1} {_ROLE_LABEL[role]}', 2))
        for row in rows[:20]:
            line = f'{_t(row.get("method"))} {_t(row.get("url"))} → {_t(row.get("status_code"))}｜sha256 {_t(row.get("body_sha256"))[:16]}…'
            body.append(_para(line, size=18))
            if row.get("request_head"):
                body.append(_code(row["request_head"]))
    if not any_traffic:
        body.append(_para("尚未绑定流量证据。可在融合层「流量留痕」页导入并绑定后重新导出。"))
    # 复测与路线图
    body.append(_heading("六、复测记录", 1))
    body.append(_para(f'审核结论：{model["review"]["verdict"]}；独立复现：{"是" if model["review"]["reproduced"] else "否"}。'))
    body.append(_para(f'审核/人工备注：{model["review"]["notes"]}'))
    body.append(_heading("七、修复路线图", 1))
    for item in model["roadmap"]:
        body.append(_para(item, bullet=True))
    body.append(_heading("八、附录：结构化证据字段", 1))
    for k, v in (model["evidence"] or {}).items():
        body.append(_para(f'{_t(k)}：{_t(v, 400)}', size=18))
    # 节属性：页眉页脚引用
    sect = ('<w:sectPr><w:headerReference w:type="default" r:id="rIdH1"/>'
            '<w:footerReference w:type="default" r:id="rIdF1"/>'
            '<w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
            'w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>')
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<w:body>{"".join(body)}{sect}</w:body></w:document>')


def _styles_xml() -> str:
    para_styles = "".join(
        f'<w:style w:type="paragraph" w:styleId="Heading{i}"><w:name w:val="heading {i}"/>'
        f'<w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>'
        f'<w:rPr><w:b/><w:sz w:val="{32 - i * 2}"/></w:rPr></w:style>'
        for i in (1, 2, 3)
    )
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>'
            f'{para_styles}'
            '<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/>'
            '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="18"/></w:rPr></w:style>'
            '</w:styles>')


def build_public_docx_bytes(model: dict) -> bytes:
    """组装完整 docx 包；返回 bytes，可直接作为附件下载。"""
    document = render_document_xml(model)
    numbering = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                 '<w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0">'
                 '<w:numFmt w:val="bullet"/><w:lvlText w:val="•"/>'
                 '<w:pPr><w:ind w:left="420" w:hanging="240"/></w:pPr></w:lvl></w:abstractNum>'
                 '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num></w:numbering>')
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    header = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              f'<w:hdr {ns}><w:p><w:pPr><w:jc w:val="right"/></w:pPr>'
              f'<w:r><w:t>{escape(model["subtitle"])} · {escape(model["classification"])}</w:t></w:r></w:p></w:hdr>')
    footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              f'<w:ftr {ns}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
              '<w:r><w:t>第 </w:t></w:r>'
              '<w:fldSimple w:instr="PAGE"><w:r><w:t>1</w:t></w:r></w:fldSimple>'
              '<w:r><w:t> 页</w:t></w:r></w:p></w:ftr>')
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                     '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                     '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
                     '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
                     '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
                     '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                     '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
                     '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>')
    doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rIdS1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                '<Relationship Id="rIdN1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
                '<Relationship Id="rIdH1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>'
                '<Relationship Id="rIdF1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
                '</Relationships>')
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<dc:title>{escape(model["title"])}</dc:title><dc:creator>知蠹 Riddle</dc:creator></cp:coreProperties>')
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>Riddle Fusion</Application></Properties>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/_rels/document.xml.rels", doc_rels)
        zf.writestr("word/document.xml", document)
        zf.writestr("word/styles.xml", _styles_xml())
        zf.writestr("word/numbering.xml", numbering)
        zf.writestr("word/header1.xml", header)
        zf.writestr("word/footer1.xml", footer)
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app)
    return buf.getvalue()
