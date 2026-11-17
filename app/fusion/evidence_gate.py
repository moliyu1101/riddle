"""证据闸门：机械验证凭据 + L1-L4 影响分级。

Riddle 已有 ``app/agents/exploit_chain.py`` 的启发式「半成品特征」拦截和
``worker._weak_write_evidence_reason``，本模块不重复那套关键词判断，补的是两件
现有链路没有的事：

1. **机械凭据**：critical/high 必须带能机械复现的凭据（curl / 原始请求响应包 /
   HTTP 状态码 / 工具命中输出），纯版本匹配、纯「可能存在」的描述一律打回；
2. **影响分级**：L1 信息 → L2 认证/越权 → L3 控制 → L4 数据/资金，
   critical 要求 L3+、high 要求 L2+，防止把信息泄露硬抬成严重漏洞。

默认只做试算与留痕，硬拦截由 ``FUSION_EVIDENCE_GATE_HARD=1`` 开启。
"""
from __future__ import annotations

import re
from typing import Any

LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}
LEVEL_LABEL = {
    "L1": "信息面（版本号/指纹/报错）",
    "L2": "认证与越权（未授权读取、身份绕过）",
    "L3": "控制面（命令执行、文件写入、接管）",
    "L4": "数据与资金影响（数据外带、批量泄露、资金变动）",
}

_L4_HINTS = ("数据外带", "批量泄露", "拖库", "资金", "转账", "余额", "订单数据", "身份信息批量")
_L3_HINTS = ("rce", "命令执行", "getshell", "webshell", "文件上传", "反序列化", "任意文件写", "接管", "提权")
_L2_HINTS = ("越权", "未授权", "认证绕过", "登录绕过", "idor", "jwt", "会话", "鉴权")
_L1_HINTS = ("信息泄露", "版本", "指纹", "报错", "路径泄露", "目录列举", "sql报错", "堆栈")

_HTTP_STATUS = re.compile(r"(?<!\d)(?:HTTP/[\d.]+\s+)?([1-5]\d{2})(?!\d)")
_CURL = re.compile(r"\bcurl\b|\bwget\b|^\s*(GET|POST|PUT|DELETE|PATCH)\s+/\S*\s+HTTP/", re.I | re.M)
_RAW_PACKET = re.compile(r"^\s*(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP/\d", re.I | re.M)
_TOOL_HIT = re.compile(r"\b(?:uid=\d+|root:|nmap|sqlmap|nuclei|httpx|whatweb|hydra)\b", re.I)


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _field(item: Any, name: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _blob(item: Any) -> str:
    if isinstance(item, dict):
        parts: list[str] = []
        for k, v in item.items():
            parts.append(_blob(v) if isinstance(v, (dict, list)) else f"{k}={_text(v)}")
        return " ".join(parts)
    out: list[str] = []
    for name in ("title", "description", "vuln_type", "affected_scope", "poc", "poc_http",
                 "raw_request", "raw_response", "owner"):
        val = getattr(item, name, None)
        if val:
            out.append(_text(val))
    steps = getattr(item, "steps", None) or []
    for step in steps:
        out.append(_blob(step))
    return " ".join(out)


def _severity(item: Any) -> str:
    val = _field(item, "severity_claimed", _field(item, "severity_final", ""))
    if hasattr(val, "value"):
        val = val.value
    return _text(val).strip().lower()


def impact_level(item: Any) -> str:
    """按漏洞文本推断影响层级；取命中的最高层，无命中按 L1。"""
    blob = _blob(item).lower()
    for level, hints in (("L4", _L4_HINTS), ("L3", _L3_HINTS), ("L2", _L2_HINTS), ("L1", _L1_HINTS)):
        if any(h in blob for h in hints):
            return level
    return "L1"


def mechanical_evidence(item: Any) -> list[str]:
    """列出能机械复现/核验的凭据类型（去重、稳定顺序）。"""
    blob = _blob(item)
    found: list[str] = []
    if _CURL.search(blob):
        found.append("可执行请求命令")
    if _RAW_PACKET.search(blob) or _text(_field(item, "poc_http", "")).strip():
        found.append("原始 HTTP 请求包")
    raw_resp = _text(_field(item, "raw_response", "")).strip()
    if raw_resp or _HTTP_STATUS.search(blob):
        found.append("真实响应/状态码")
    if _TOOL_HIT.search(blob):
        found.append("工具命中输出")
    steps = _field(item, "steps", []) or []
    if any(_text(_field(s, "poc", "")).strip() or _text(_field(s, "poc_http", "")).strip()
           for s in steps if isinstance(s, (dict, object)) and not isinstance(s, str)):
        found.append("分步复现 PoC")
    evidence = _field(item, "evidence", {}) or {}
    if isinstance(evidence, dict) and any(_text(v).strip() for v in evidence.values()):
        found.append("结构化证据字段")
    return found


def check_finding(item: Any) -> dict:
    """试算一条 finding 能否通过证据闸门。纯函数，不落库。"""
    severity = _severity(item)
    level = impact_level(item)
    evidence = mechanical_evidence(item)
    reasons: list[str] = []
    required_level = None
    if severity in ("critical", "严重"):
        required_level = "L3"
    elif severity in ("high", "高危"):
        required_level = "L2"
    if required_level and not evidence:
        reasons.append(f"{severity} 漏洞缺少任何机械可复现凭据（curl / 原始请求响应包 / 状态码 / 工具命中输出）")
    if required_level and LEVEL_ORDER[level] < LEVEL_ORDER[required_level]:
        reasons.append(f"影响层级 {level}（{LEVEL_LABEL[level]}）低于 {severity} 要求的 {required_level}")
    return {
        "allowed": not reasons,
        "severity": severity,
        "impact_level": level,
        "impact_label": LEVEL_LABEL[level],
        "required_level": required_level,
        "evidence": evidence,
        "reasons": reasons,
    }


def evaluate_findings(items: list[Any]) -> dict:
    """批量试算，返回统计与逐条结论。"""
    rows = [check_finding(i) for i in (items or [])]
    blocked = [r for r in rows if not r["allowed"]]
    return {
        "total": len(rows),
        "passed": len(rows) - len(blocked),
        "blocked": len(blocked),
        "rows": rows,
        "levels": {lv: sum(1 for r in rows if r["impact_level"] == lv) for lv in LEVEL_ORDER},
    }
