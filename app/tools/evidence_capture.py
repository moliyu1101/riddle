"""自动存证快照：提交漏洞时自动抓取目标页面 HTTP 快照作为存证。

真实浏览器截图需 playwright+chromium（容器内默认不可用，guard 禁止 pyppeteer/selenium）；
这里落地为「结构化 HTTP 快照」——状态码/响应头/正文片段/标题/可见文本/耗时，零依赖、
可复现，SRC 平台同样认可。快照写入 finding.evidence.snapshot 并持久化到
work_dir/evidence/ 供报告引用。

- capture_snapshot   : 抓取单个 URL 的结构化快照（复用 executor.http_request，走会话）
- capture_evidence   : capture_evidence 工具实现，抓取 + 持久化 + 返回 evidence_ref
- save/load_snapshot : 快照持久化到 work_dir/evidence/（JSON + 原始 HTML）
- render_snapshot_markdown : 报告渲染（markdown 文本块）
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# 快照体积上限：正文 HTML 与可见文本都截断，避免撑爆 finding 载荷与报告。
_BODY_SNIPPET_LIMIT = 4000
_VISIBLE_TEXT_LIMIT = 2000
_TITLE_LIMIT = 200
_META_LIMIT = 300

# 只保留对取证有用的响应头，避免整包头撑爆载荷。
_HEADER_KEEP = (
    "content-type", "server", "x-powered-by", "x-aspnet-version",
    "set-cookie", "location", "www-authenticate", "x-frame-options",
    "content-security-policy", "x-request-id", "x-runtime",
)

# 存证只抓一次，不重复请求目标。
_SNAPSHOT_MAX_REQUESTS = 1


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:_TITLE_LIMIT]


def _extract_meta(body: str) -> str:
    """提取 meta description（name 在 content 前/后两种写法都兼容）。"""
    body = body or ""
    m = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]*content=["\'](.*?)["\']',
        body, re.IGNORECASE | re.DOTALL,
    )
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\'](.*?)["\'][^>]*name=["\']description["\']',
            body, re.IGNORECASE | re.DOTALL,
        )
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:_META_LIMIT]


def _extract_visible_text(body: str, max_len: int = _VISIBLE_TEXT_LIMIT) -> str:
    """剥掉 script/style/注释/标签，取页面可见文本片段。"""
    text = re.sub(r"<script[\s\S]*?</script>", " ", body or "", flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<!--[\s\S]*?-->", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def _pick_headers(headers: dict) -> dict:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k.lower() in _HEADER_KEEP:
            out[k] = str(v)[:300]
    return out


def capture_snapshot(
    executor: Any,
    url: str,
    method: str = "GET",
    data: str = "",
    timeout: int = 15,
    body_limit: int = _BODY_SNIPPET_LIMIT,
) -> dict[str, Any]:
    """抓取目标页面 HTTP 快照：状态/响应头/正文片段/标题/可见文本/耗时。

    走 executor.http_request（自动携带已维持的会话 cookie），只读为主；
    失败返回 ok=False，不抛异常，不阻塞提交。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    t0 = time.time()
    try:
        resp = executor.http_request(
            url, method=method, data=data or None, timeout=int(timeout or 15),
        )
    except Exception as e:
        return {"ok": False, "error": f"存证快照抓取异常: {type(e).__name__}: {e}", "url": url}
    elapsed = round(time.time() - t0, 2)
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error") or "存证快照抓取失败。", "url": url}
    body = resp.get("body") or ""
    return {
        "ok": True,
        "url": resp.get("url") or url,
        "method": method.upper(),
        "status": int(resp.get("status_code") or 0),
        "headers": _pick_headers(resp.get("response_headers") or {}),
        "body_len": int(resp.get("body_len") or len(body)),
        "elapsed": elapsed,
        "title": _extract_title(body),
        "meta_description": _extract_meta(body),
        "visible_text": _extract_visible_text(body),
        "body_snippet": body[:body_limit],
        "captured_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    }


def snapshot_to_text(snapshot: dict, max_len: int = 1500) -> str:
    """把快照渲染成紧凑文本（供 LLM 工具返回 / 报告正文）。"""
    if not snapshot or not snapshot.get("ok"):
        return "（存证快照抓取失败）"
    lines = [
        f"存证快照 @ {snapshot.get('url') or '-'}",
        f"状态码: {snapshot.get('status') or '-'} | 正文: {snapshot.get('body_len') or 0}B | 耗时: {snapshot.get('elapsed') or '-'}s",
    ]
    if snapshot.get("title"):
        lines.append(f"标题: {snapshot['title']}")
    if snapshot.get("meta_description"):
        lines.append(f"描述: {snapshot['meta_description']}")
    hdrs = snapshot.get("headers") or {}
    if hdrs:
        lines.append("响应头: " + "; ".join(f"{k}={v}" for k, v in list(hdrs.items())[:6]))
    if snapshot.get("visible_text"):
        lines.append(f"可见文本: {snapshot['visible_text'][:600]}")
    text = "\n".join(lines)
    return text[:max_len]


def save_snapshot(work_dir: Any, snapshot: dict) -> str:
    """持久化快照到 work_dir/evidence/，返回相对引用（evidence/snap_<ts>.json）。

    同时落一份原始 HTML 片段（.html），供人工复核/报告引用。
    """
    if not snapshot or not snapshot.get("ok"):
        return ""
    base = Path(work_dir) / "evidence"
    base.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    ref = f"evidence/snap_{ts}_{abs(hash(snapshot.get('url') or '')) % 10000}.json"
    payload = {**snapshot}
    payload.pop("body_snippet", None)  # 原始 HTML 单独落盘，JSON 只留引用
    (base / Path(ref).name).write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8",
    )
    html_name = Path(ref).stem + ".html"
    (base / html_name).write_text(
        (snapshot.get("body_snippet") or ""), encoding="utf-8",
    )
    return ref


def load_snapshot(work_dir: Any, ref: str) -> dict | None:
    """按相对引用加载持久化快照（含 body_snippet 从 .html 回填）。"""
    ref = (ref or "").strip()
    if not ref:
        return None
    base = Path(work_dir) / "evidence"
    p = base / Path(ref).name
    if not p.exists():
        return None
    try:
        snap = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    html_p = p.with_suffix(".html")
    if html_p.exists():
        try:
            snap["body_snippet"] = html_p.read_text(encoding="utf-8")[:_BODY_SNIPPET_LIMIT]
        except Exception:
            pass
    return snap


def render_snapshot_markdown(snapshot: dict) -> str:
    """报告用 markdown 文本块（含原始 HTML 片段）。"""
    if not snapshot or not snapshot.get("ok"):
        return "（存证快照抓取失败）"
    lines = [
        f"URL: {snapshot.get('url') or '-'}",
        f"状态码: {snapshot.get('status') or '-'}",
        f"正文长度: {snapshot.get('body_len') or 0} B",
        f"耗时: {snapshot.get('elapsed') or '-'} s",
        f"抓取时间: {snapshot.get('captured_at') or '-'}",
    ]
    if snapshot.get("title"):
        lines.append(f"页面标题: {snapshot['title']}")
    if snapshot.get("meta_description"):
        lines.append(f"页面描述: {snapshot['meta_description']}")
    hdrs = snapshot.get("headers") or {}
    if hdrs:
        lines.append("关键响应头:")
        lines.extend(f"  {k}: {v}" for k, v in hdrs.items())
    if snapshot.get("visible_text"):
        lines.append("可见文本:")
        lines.append(snapshot["visible_text"])
    if snapshot.get("body_snippet"):
        lines.append("原始 HTML 片段:")
        lines.append(snapshot["body_snippet"])
    return "\n".join(lines)


def capture_evidence(
    executor: Any,
    url: str = "",
    method: str = "GET",
    data: str = "",
    timeout: int = 15,
) -> dict[str, Any]:
    """capture_evidence 工具实现：抓取指定 URL 存证快照并持久化，返回摘要 + evidence_ref。

    worker 在确认漏洞后调用，把返回的 evidence_ref 通过 submit_finding 的
    evidence.snapshot_ref 带上，提交时自动合并进报告证据链。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空：要存证的页面地址。"}
    snap = capture_snapshot(executor, url, method=method, data=data, timeout=timeout)
    if not snap.get("ok"):
        return {"ok": False, "error": snap.get("error") or "存证快照抓取失败。", "url": url}
    ref = save_snapshot(executor.work_dir, snap)
    return {
        "ok": True,
        "url": url,
        "status": snap.get("status") or 0,
        "title": snap.get("title") or "",
        "body_len": snap.get("body_len") or 0,
        "evidence_ref": ref,
        "summary": (
            f"存证快照已保存：{url} → HTTP {snap.get('status') or '-'}，"
            f"标题「{snap.get('title') or '-'}」，正文 {snap.get('body_len') or 0}B。"
        ),
        "guidance": (
            "在 submit_finding 的 evidence 里带上 snapshot_ref 引用该存证"
            "（如 evidence: {\"snapshot_ref\": \"...\"}），提交时会自动合并进报告证据链。"
        ),
    }
