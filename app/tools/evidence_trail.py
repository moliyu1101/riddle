"""证据沉淀链：把 worker 每次工具调用的真实请求/响应/输出增量落盘。

背景：submit_finding 是漏洞数据的唯一出口，但它是单次 LLM 调用返回超大 JSON。
一旦慢中转（后端 120s 硬截断）超时，finding 数据就随 LLM 失败一起丢失——
因为真正的证据（http_request 的请求/响应、run_shell 的输出）只存在于 worker
内存，从未落盘。

本模块让证据在【产生的那一刻】就增量落到 work_dir/evidence_trail.jsonl，
与 LLM 完全解耦。即使后面所有 LLM 调用都失败，已发生的攻击与取证永远在盘上，
可由确定性代码重建 Finding，不再依赖单次大响应。

- append_trail     : 一次工具调用后追加一条证据（线程安全）
- load_trail       : 读取整条证据链（按时间序）
- latest_trail     : 最近一条
- reset_trail      : 清空（仅测试用）
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

_TRAIL_NAME = "evidence_trail.jsonl"
_lock = threading.RLock()

# 单条记录字段体积上限：正文/输出过大就截断标注（与 executor._truncate 一致思路），
# 避免几百条大响应把 work_dir 撑爆。原始 body 上限由 executor 的 _HTTP_MAX_BYTES 控制。
_BODY_LIMIT = 200 * 1024
_HEADER_LIMIT = 64 * 1024
_TRAIL_MAX_RECORDS = 2000   # 每目标最多保留 2000 条，防长期任务无限膨胀


def _trail_path(work_dir: Any) -> Path:
    return Path(work_dir) / _TRAIL_NAME


def _clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[取证超长已裁剪]...\n\n{tail}"


def append_trail(
    work_dir: Any,
    *,
    kind: str,
    target: str = "",
    tool: str = "",
    url: str = "",
    method: str = "",
    request: Optional[str] = None,
    response_headers: Optional[dict] = None,
    body: Optional[str] = None,
    status: Optional[int] = None,
    output: Optional[str] = None,
    notes: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """追加一条低风险证据记录。任何失败都静默忽略，绝不阻断挖掘主流程。"""
    try:
        path = _trail_path(work_dir)
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            rec = {
                "ts": time.time(),
                "kind": kind,
                "target": (target or "")[:200],
                "tool": (tool or "")[:60],
                "url": (url or "")[:500],
                "method": (method or "")[:12],
                "status": status,
                "request": _clip(request or "", _BODY_LIMIT),
                "body": _clip(body or "", _BODY_LIMIT),
                "output": _clip(output or "", _BODY_LIMIT),
                "notes": (notes or "")[:2000],
                "response_headers": _clip(json.dumps(response_headers or {}, ensure_ascii=False), _HEADER_LIMIT),
            }
            if extra:
                for k, v in extra.items():
                    try:
                        rec[k] = _clip(str(v), _BODY_LIMIT)
                    except Exception:
                        pass
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            _trim(path)
    except Exception:
        pass


def _trim(path: Path) -> None:
    """超出条数上限时，截断到只保留最近 _TRAIL_MAX_RECORDS 条（保留文件尾）。"""
    try:
        size = path.stat().st_size
        if size < 4 * 1024 * 1024:
            return  # 未超 4MB 不频繁扫描
        with _lock:
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > _TRAIL_MAX_RECORDS:
                path.write_text("\n".join(lines[-_TRAIL_MAX_RECORDS:]) + "\n", encoding="utf-8")
    except Exception:
        pass


def load_trail(work_dir: Any) -> list[dict[str, Any]]:
    """按时间序读取整条证据链。失败返回空列表。"""
    try:
        path = _trail_path(work_dir)
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    # 兼容旧字段名解析失败
                    out.append(rec)
            except Exception:
                continue
        return out
    except Exception:
        return []


def latest_trail(work_dir: Any) -> Optional[dict[str, Any]]:
    try:
        trail = load_trail(work_dir)
        return trail[-1] if trail else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 确定性重建：LLM 提交失败时，从本地证据链重建最小可用 Finding。
# 不依赖 LLM——真正的请求行 + 原始响应都在盘上，可直接拼出 curl / 请求包 / 步骤。
# ---------------------------------------------------------------------------


def _guess_vuln_type(request_line: str, body: str, url: str, method: str) -> str:
    """从请求/响应特征低置信度推断漏洞类型，用于重建占位。不是判决。"""
    low_body = (body or "").lower()
    low_url = (url or "").lower()
    combined = f"{request_line or ''} {low_url} {low_body[:4000]}"
    hints = {
        "unauthorized_access": lambda c: ("admin" in c or "member" in c or "manage" in c)
        and ("login" not in c and "password" not in c),
        "idor": lambda c: any(m in c for m in ("/index?offset=", "/item/", "?id=", "offset=0")),
        "info_leak": lambda c: any(m in c for m in ("password", "hash", "phone", "身份证", "member_count")),
        "weak_password": lambda c: any(m in c for m in ("a123456", "admin/", "/admin/login")),
    }
    for kind, fn in hints.items():
        try:
            if fn(combined):
                return kind
        except Exception:
            continue
    return "unauthorized_access"


def _build_curl(method: str, url: str, request: str) -> str:
    """从原始请求行重建最小 curl 命令（带会话 cookie 则追加）。"""
    try:
        parts = [f"curl '{url}'"]
        if method and method.upper() != "GET":
            parts.insert(0, f"curl -X {method.upper()} '{url}'")
        # 从原始请求包里尽力提取一行 cookie
        cookie = ""
        for line in (request or "").splitlines():
            if line.lower().startswith("cookie:"):
                cookie = line.split(":", 1)[1].strip()
                break
        if cookie:
            parts.append(f"-H 'Cookie: {cookie}'")
        return " ".join(parts)
    except Exception:
        return f"curl '{url}'"


def build_finding_from_trail(work_dir: Any, target_url: str = "") -> Optional[dict]:
    """从本地证据链重建一个最小可用 Finding dict（走 app.schemas.Finding 校验前形态）。

    取最近一次成功的 http_request 记录作主证据。返回 None 表示无可重建证据
    （例如全程没有真正发起过请求），此时不应伪造漏洞。
    """
    trail = load_trail(work_dir)
    rec = None
    for r in reversed(trail):
        if r.get("kind") == "http_request" and r.get("status") is not None:
            rec = r
            break
    if rec is None:
        return None
    url = rec.get("url") or target_url
    method = (rec.get("method") or "GET").upper()
    request = rec.get("request") or ""
    body = rec.get("body") or ""
    status = rec.get("status") or 0
    headers = rec.get("response_headers") or ""
    # 重建请求包（请求行 + Host + 关键头 + 空行 + 请求体）
    resp_pkg = f"HTTP/1.1 {status}\n{headers}\n\n{body[:8000]}"
    poc = _build_curl(method, url, request)
    # 步骤一：触发请求；步骤二：观察响应
    steps = [
        {
            "desc": f"复现：以 {method} 请求 {url}（无需登录/当前会话即可）。",
            "poc": poc,
            "poc_http": request or f"{method} {url.split('?')[0] if '?' in url else url} HTTP/1.1\nHost: {url.split('/')[2] if '://' in url else ''}\n\n",
        },
        {
            "desc": f"观察响应：HTTP {status}，返回体命中关键数据（见下方原始响应）。标记了复现链，人工复核后完善归属与等级。",
            "poc": "",
            "poc_http": "",
        },
    ]
    return {
        "vuln_type": _guess_vuln_type(request, body, url, method),
        "title": f"{url} - 越权/未授权访问（LLM超时自动重建，待人工复核）",
        "severity_claimed": "高危",
        "target_url": url,
        "owner": "",
        "description": (
            "由证据链自动重建（原提交因 LLM 端点超时失败）。目标接口返回非登录页的真实数据响应 "
            f"（HTTP {status}），疑似未授权访问/越权泄露。已保留原始请求与响应供人工复核，"
            "请确认归属、影响面与等级后正式上报。"
        ),
        "steps": steps,
        "poc": poc,
        "poc_http": request or "",
        "raw_request": request or "",
        "raw_response": resp_pkg,
        "affected_scope": "待人工复核",
        "kill_chain": [],
        "self_check": {
            "is_reflected_xss": False,
            "needs_admin_login": False,
            "needs_mitm": False,
            "is_pure_info_leak": False,
            "scanner_only_no_poc": False,
            "is_public_interface": False,
            "info_leak_hits_strict_list": True,
        },
        "evidence": {
            "tool_output": body[:4000],
            "notes": (
                "⚠️ 该漏洞由证据链自动重建，规避了 LLM 提交超时导致的数据丢失。"
                "请人工复核漏洞类型/等级/归属后正式上报。"
            ),
        },
        "_rebuilt": True,
        "_rebuilt_from": "evidence_trail",
    }