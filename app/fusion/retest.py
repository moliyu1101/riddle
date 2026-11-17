"""漏洞复测闭环：支持手动复测登记与经 SSRF 守卫校验的安全 HTTP 只读复测。

复测历史持久化于 ``Finding.evidence["retests"]``（零表结构变更），并同步进入
``docx_report``「六、复测记录」章节与报告抽屉。
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.tools.netguard import assert_safe_outbound_url

RETEST_STATUSES = ("reproduced", "fixed", "partial", "error")
STATUS_LABEL = {
    "reproduced": "仍可复现（未修复）",
    "fixed": "已修复",
    "partial": "部分缓解",
    "error": "探测异常",
}

Requester = Callable[[str, str, dict[str, str]], Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sha256_text(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def create_manual_retest(
    status: str,
    *,
    notes: str = "",
    status_code: int = 0,
    url: str = "",
    method: str = "GET",
    response_excerpt: str = "",
) -> dict[str, Any]:
    """创建一条手动复测记录；非法状态抛 ValueError。"""
    st = str(status or "").strip().lower()
    if st not in RETEST_STATUSES:
        raise ValueError(f"非法的复测状态 {st!r}，允许：{RETEST_STATUSES}")
    excerpt = str(response_excerpt or "")[:300]
    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        code = 0
    return {
        "id": uuid.uuid4().hex[:12],
        "mode": "manual",
        "status": st,
        "status_label": STATUS_LABEL[st],
        "status_code": code,
        "method": (str(method or "GET").strip().upper() or "GET")[:10],
        "url": str(url or "").strip()[:500],
        "match_text": "",
        "response_sha256": _sha256_text(excerpt),
        "response_excerpt": excerpt,
        "notes": str(notes or "").strip()[:500],
        "created_at": _now_iso(),
    }


def _default_requester(method: str, url: str, headers: dict[str, str]) -> Any:
    import httpx

    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        return client.request(method, url, headers=headers)


def _extract_response(resp: Any) -> tuple[int, str]:
    if isinstance(resp, dict):
        code = int(resp.get("status_code") or resp.get("status") or 0)
        body = resp.get("text")
        if body is None:
            body = resp.get("body") or ""
        return code, str(body)
    code = int(getattr(resp, "status_code", 0) or 0)
    body = getattr(resp, "text", None)
    if body is None and hasattr(resp, "content"):
        raw = getattr(resp, "content") or b""
        body = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return code, str(body or "")


def run_http_retest_probe(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    match_text: str = "",
    requester: Requester | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """发起受 SSRF netguard 保护的单次安全只读复测请求并判定状态。"""
    clean_url = assert_safe_outbound_url(str(url or "").strip())
    clean_method = (str(method or "GET").strip().upper() or "GET")[:10]
    if clean_method not in ("GET", "HEAD", "OPTIONS", "POST"):
        raise ValueError(f"复测探测仅支持 GET/HEAD/OPTIONS/POST，收到 {clean_method!r}")
    req_headers = {str(k): str(v) for k, v in (headers or {}).items() if str(k).strip()}
    fn = requester or _default_requester

    code = 0
    body = ""
    err_note = ""
    try:
        resp = fn(clean_method, clean_url, req_headers)
        code, body = _extract_response(resp)
    except Exception as exc:
        err_note = f"{type(exc).__name__}: {exc}"

    excerpt = body[:300]
    marker = str(match_text or "").strip()
    if err_note:
        status = "error"
    elif marker:
        if marker in body and 200 <= code < 400:
            status = "reproduced"
        elif marker in body:
            status = "partial"
        elif 200 <= code < 500:
            status = "fixed"
        else:
            status = "error"
    else:
        if 200 <= code < 300:
            status = "reproduced"
        elif code in (401, 403, 404, 410):
            status = "fixed"
        elif 300 <= code < 500:
            status = "partial"
        else:
            status = "error"

    final_notes = str(notes or "").strip()
    if err_note:
        final_notes = f"{final_notes} | {err_note}".strip(" |")
    elif not final_notes:
        final_notes = f"HTTP {code}" + (f"，匹配关键字 {'命中' if (marker and marker in body) else '未命中'}" if marker else "")

    return {
        "id": uuid.uuid4().hex[:12],
        "mode": "http_probe",
        "status": status,
        "status_label": STATUS_LABEL[status],
        "status_code": code,
        "method": clean_method,
        "url": clean_url[:500],
        "match_text": marker[:120],
        "response_sha256": _sha256_text(body),
        "response_excerpt": excerpt,
        "notes": final_notes[:500],
        "created_at": _now_iso(),
    }


def get_finding_retests(finding: Any) -> list[dict[str, Any]]:
    ev = finding.get("evidence") if isinstance(finding, dict) else getattr(finding, "evidence", None)
    if not isinstance(ev, dict):
        return []
    raw = ev.get("retests")
    if not isinstance(raw, list):
        return []
    return [dict(item) for item in raw if isinstance(item, dict)]


def summarize_retests(retests: list[dict[str, Any]] | None) -> dict[str, Any]:
    rows = list(retests or [])
    counts = {k: 0 for k in RETEST_STATUSES}
    for r in rows:
        st = str(r.get("status") or "")
        if st in counts:
            counts[st] += 1
    latest = rows[-1] if rows else {}
    return {
        "total": len(rows),
        "latest_status": str(latest.get("status") or ""),
        "latest_label": str(latest.get("status_label") or ""),
        "latest_at": str(latest.get("created_at") or ""),
        "reproduced_count": counts["reproduced"],
        "fixed_count": counts["fixed"],
        "counts": counts,
    }
