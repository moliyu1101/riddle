"""知蠹 Riddle 内置应用层 WAF。

设计目标：
- 拦截公网常见扫描/注入/路径穿越/异常 Header/方法滥用/请求体过大/高频请求。
- 不直接扫描报告正文，避免把正常保存的漏洞 PoC、raw_response、curl payload 误杀。
- 与访问令牌鉴权叠加：WAF 先挡明显攻击，鉴权再做读写权限隔离。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlencode

from fastapi import Request


def _env_bool(name: str, default: bool = True) -> bool:
    return os.environ.get(name, "1" if default else "0").lower() not in {"0", "false", "no", "off"}


WAF_ENABLED = _env_bool("RIDDLE_WAF_ENABLED", True)
WAF_BLOCK_MODE = _env_bool("RIDDLE_WAF_BLOCK", True)
TRUST_PROXY_HEADERS = _env_bool("RIDDLE_TRUST_PROXY", False)
MAX_CONTENT_LENGTH = int(os.environ.get("RIDDLE_WAF_MAX_BODY", str(2 * 1024 * 1024)))
# 备份恢复要上传整库 tar.gz（生产库常 >100MB），单独放宽；其它接口仍走上面的 2MB。
BACKUP_MAX_CONTENT_LENGTH = int(os.environ.get("RIDDLE_BACKUP_MAX_BODY", str(8 * 1024 * 1024 * 1024)))
_BACKUP_UPLOAD_PATHS = frozenset({"/api/backup/restore"})

_STATIC_PREFIXES = ("/assets/",)
_EXACT_ALLOW = {"/", "/health", "/favicon.svg", "/favicon.ico", "/api/auth/status"}
_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_MAX_HEADER_VALUE = 8192
_MAX_PATH_LEN = 2048
_SEARCH_ENDPOINTS = re.compile(
    r"^/api/tasks/[^/]+/(?:results|review-queue|submit-list|rejected|killsweeps)$"
)

_BAD_UA = re.compile(
    r"(?:acunetix|appscan|awvs|dirbuster|gobuster|nikto|nuclei|sqlmap|wpscan|zgrab|masscan|nessus|xray)",
    re.I,
)

_PATH_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", re.I)),
    ("sensitive_file_probe", re.compile(r"(?:^|/)(?:\.env|\.git|id_rsa|passwd|shadow|web\.config|phpinfo\.php)(?:$|[/?])", re.I)),
    ("framework_probe", re.compile(r"(?:/wp-admin|/wp-login\.php|/phpmyadmin|/actuator/env|/debug/pprof|/server-status)", re.I)),
    ("encoded_scheme", re.compile(r"(?:file|gopher|dict|ldap|jar|php|data):/{0,2}", re.I)),
]

_QUERY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("path_traversal_query", re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", re.I)),
    ("encoded_scheme_query", re.compile(r"(?:file|gopher|dict|ldap|jar|php|data):/{0,2}", re.I)),
    ("sqli_union", re.compile(r"(?:\bunion\b.{0,80}\bselect\b|\bselect\b.{0,80}\bfrom\b)", re.I | re.S)),
    # token 限长：无界贪心 token 在长 query 上有 O(n²) 回溯空间（中间件每请求执行，可放大 CPU）
    ("sqli_boolean", re.compile(r"(?:\bor\b|\band\b)\s+[\w'\"()]{1,64}\s*=\s*[\w'\"()]{1,64}", re.I)),
    ("sqli_time", re.compile(r"(?:sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)", re.I)),
    ("xss_probe", re.compile(r"(?:<\s*script\b|onerror\s*=|onload\s*=|javascript:|data:text/html)", re.I)),
    ("rce_probe", re.compile(r"(?:\b(?:cat|bash|sh|curl|wget|nc|python|perl)\b.{0,60}(?:/etc/passwd|bash -i|/bin/sh)|\$\{jndi:)", re.I | re.S)),
    # 无界 .*（re.S）在 8KB 无闭合 {{ 上最坏指数级回溯；改否定字符类 + 表达式限长。
    # WAF 只是纵深，超长模板表达式漏检可接受（真正防线是参数化与出口转义）。
    ("template_probe", re.compile(r"\{\{[^{}]{0,200}?(?:config|class|constructor|self)[^{}]{0,200}?\}\}|\$\{[^${}]{0,200}?(?:T\(|Runtime|jndi)[^${}]{0,200}?\}", re.I)),
]

_HEADER_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("log4shell_header", re.compile(r"\$\{jndi:", re.I)),
    ("proxy_smuggling", re.compile(r"(?:\r|\n|%0d|%0a)", re.I)),
]


@dataclass
class WAFDecision:
    allowed: bool
    reason: str = ""
    status_code: int = 403


def _client_ip(request: Request) -> str:
    # 默认直连公网，不信任客户端可伪造的 X-Forwarded-For；放到可信反代后再显式开启。
    forwarded = request.headers.get("x-forwarded-for", "") if TRUST_PROXY_HEADERS else ""
    if forwarded:
        return forwarded.split(",", 1)[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _normalized_path(request: Request) -> str:
    raw = request.url.path
    return _multi_unquote(raw)[:_MAX_PATH_LEN]


def _multi_unquote(text: str, rounds: int = 5) -> str:
    """循环百分号解码直到稳定（上限 5 层）：固定两层解码会让三层及以上的
    编码 payload（如 %25253Cscript）穿透规则匹配。"""
    out = text
    for _ in range(rounds):
        dec = unquote(out)
        if dec == out:
            break
        out = dec
    return out


def _query_for_inspection(request: Request) -> str:
    raw = request.url.query or ""
    if not raw:
        return ""
    pairs = parse_qsl(raw, keep_blank_values=True)
    if _SEARCH_ENDPOINTS.match(request.url.path):
        # 报告搜索是正常业务入口，用户经常搜索 SQLi/XSS/RCE payload。
        # 只跳过 q 本身，其它控制参数仍接受 WAF 检查。
        pairs = [(k, v) for k, v in pairs if k != "q"]
    return _multi_unquote(urlencode(pairs))[:8192]


def inspect_request(request: Request) -> WAFDecision:
    if not WAF_ENABLED:
        return WAFDecision(True)

    path = request.url.path
    method = request.method.upper()
    if path == "/dpskapi" or path.startswith("/dpskapi/"):
        return WAFDecision(True)
    if path == "/workfiles" or path.startswith("/workfiles/"):
        # 工作目录静态文件：路径由 app/workfiles.resolve_workfile 做越界校验与
        # 内容消毒，不再做攻击特征匹配（目标目录名可能天然含 wp-admin/.env/
        # phpinfo.php 等片段，按特征拦截会误杀正常截图/证据加载）。
        return WAFDecision(True)
    ip = _client_ip(request)

    if method not in _ALLOWED_METHODS:
        return WAFDecision(False, "method_not_allowed", 405)
    if len(path) > _MAX_PATH_LEN:
        return WAFDecision(False, "path_too_long", 414)

    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit():
        limit = BACKUP_MAX_CONTENT_LENGTH if path in _BACKUP_UPLOAD_PATHS else MAX_CONTENT_LENGTH
        if int(content_length) > limit:
            return WAFDecision(False, "body_too_large", 413)

    ua = request.headers.get("user-agent", "")
    if _BAD_UA.search(ua):
        return WAFDecision(False, "scanner_user_agent")

    for name, value in request.headers.items():
        if len(value) > _MAX_HEADER_VALUE:
            return WAFDecision(False, f"header_too_large:{name}", 431)
        sample = f"{name}: {value}"[:12000]
        for rule, pat in _HEADER_RULES:
            if pat.search(sample):
                return WAFDecision(False, rule)

    normalized_path = _normalized_path(request)
    for rule, pat in _PATH_RULES:
        if pat.search(normalized_path):
            return WAFDecision(False, rule)

    # 静态/健康路径只做基础检查；业务查询参数做注入探测。
    if path in _EXACT_ALLOW or path.startswith(_STATIC_PREFIXES):
        return WAFDecision(True)

    query = _query_for_inspection(request)
    for rule, pat in _QUERY_RULES:
        if query and pat.search(query):
            return WAFDecision(False, rule)

    return WAFDecision(True)


def waf_headers(decision: WAFDecision) -> dict[str, str]:
    base = {
        "X-Riddle-WAF": "on",
        "X-Riddle-WAF-Mode": "block" if WAF_BLOCK_MODE else "monitor",
    }
    if decision.reason:
        base["X-Riddle-WAF-Reason"] = decision.reason[:80]
    return base
