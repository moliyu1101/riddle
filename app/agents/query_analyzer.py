"""查询条件解析分析：供新建/编辑任务前端实时反馈（不落库）。

复用 engines/translator.parse_fofa_query 做 FOFA 风格（field="value"）token 解析，
并补充冒号风格（field:value，Quake/Shodan/Censys）解析；再给出：
括号/引号闭合校验、未知字段提示、引擎语法风格/不匹配检测、字段速查表、
关键词分类提取、一句话描述。
"""
from __future__ import annotations

import re

from app.engines.translator import parse_fofa_query

# 冒号风格 token：field:value / field:"value"，token 边界匹配，避免把 http:// 误判
_COLON_TOKEN_RE = re.compile(
    r'(?:^|[\s(])([a-zA-Z_][\w.]*)\s*:\s*(?![/=])'
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s&|()]+)'
)

# 各引擎语法风格：等号（FOFA 系）还是冒号（Quake 系）
_ENGINE_STYLE: dict[str, dict[str, str]] = {
    "fofa": {"joiner": "=", "label": "FOFA", "hint": 'FOFA 用 field="value"，&& / || 连接条件'},
    "quake": {"joiner": ":", "label": "Quake", "hint": "Quake 用 field:value，AND / OR 连接条件"},
    "hunter": {"joiner": "=", "label": "Hunter", "hint": 'Hunter 用 field="value"，&& / || 连接条件'},
    "zoomeye": {"joiner": "=", "label": "ZoomEye", "hint": 'ZoomEye v2 用 field="value"，&& / || 连接条件'},
    "shodan": {"joiner": ":", "label": "Shodan", "hint": "Shodan 用 filter:value，空格连接条件"},
    "censys": {"joiner": ":", "label": "Censys", "hint": "Censys 用 field: value，and / or 连接条件"},
}

# 各引擎常用字段速查（前端渲染成可点击 chips）
_FIELD_SHEET: dict[str, list[dict[str, str]]] = {
    "fofa": [
        {"field": "title", "label": "标题", "example": 'title="统一身份认证"'},
        {"field": "domain", "label": "域名", "example": 'domain=".edu.cn"'},
        {"field": "org", "label": "组织", "example": 'org="某大学"'},
        {"field": "cert", "label": "证书", "example": 'cert="某大学"'},
        {"field": "ip", "label": "IP", "example": 'ip="1.2.3.4"'},
        {"field": "port", "label": "端口", "example": 'port="443"'},
        {"field": "app", "label": "应用", "example": 'app="泛微OA"'},
        {"field": "icon_hash", "label": "图标", "example": 'icon_hash="-123456789"'},
    ],
    "quake": [
        {"field": "title", "label": "标题", "example": 'title:"登录"'},
        {"field": "domain", "label": "域名", "example": 'domain:"edu.cn"'},
        {"field": "org", "label": "组织", "example": 'org:"某大学"'},
        {"field": "ip", "label": "IP", "example": 'ip:"1.2.3.4"'},
        {"field": "port", "label": "端口", "example": 'port:"443"'},
        {"field": "service.name", "label": "服务", "example": 'service.name:"http"'},
        {"field": "favicon", "label": "图标", "example": 'favicon:"-123456789"'},
    ],
    "hunter": [
        {"field": "web.title", "label": "网页标题", "example": 'web.title="统一身份认证"'},
        {"field": "domain.suffix", "label": "域名后缀", "example": 'domain.suffix="edu.cn"'},
        {"field": "web.body", "label": "网页正文", "example": 'web.body="登录"'},
        {"field": "ip.isp", "label": "ISP", "example": 'ip.isp="中国教育网"'},
        {"field": "ip.company", "label": "单位", "example": 'ip.company="某大学"'},
        {"field": "web.app", "label": "应用", "example": 'web.app="泛微OA"'},
        {"field": "web.status_code", "label": "状态码", "example": 'web.status_code="200"'},
    ],
    "zoomeye": [
        {"field": "title", "label": "标题", "example": 'title="登录"'},
        {"field": "domain", "label": "域名", "example": 'domain="edu.cn"'},
        {"field": "org", "label": "组织", "example": 'org="某大学"'},
        {"field": "ip", "label": "IP", "example": 'ip="1.2.3.4"'},
        {"field": "port", "label": "端口", "example": 'port="443"'},
        {"field": "app", "label": "应用", "example": 'app="泛微OA"'},
        {"field": "iconhash", "label": "图标", "example": 'iconhash="-123456789"'},
    ],
    "shodan": [
        {"field": "http.title", "label": "标题", "example": 'http.title:"login"'},
        {"field": "hostname", "label": "主机名", "example": "hostname:edu.cn"},
        {"field": "org", "label": "组织", "example": 'org:"China Education and Research Network"'},
        {"field": "net", "label": "网段", "example": "net:1.2.3.0/24"},
        {"field": "port", "label": "端口", "example": "port:443"},
        {"field": "product", "label": "产品", "example": 'product:"nginx"'},
        {"field": "ssl.cert", "label": "证书", "example": 'ssl.cert.subject.cn:"example.edu.cn"'},
    ],
    "censys": [
        {"field": "host.services.http.response.html_title", "label": "标题", "example": 'host.services.http.response.html_title:"Login"'},
        {"field": "host.dns.names", "label": "域名", "example": "host.dns.names: edu.cn"},
        {"field": "host.ip", "label": "IP", "example": "host.ip: 1.2.3.4"},
        {"field": "host.services.port", "label": "端口", "example": "host.services.port: 443"},
        {"field": "host.autonomous_system.organization", "label": "组织", "example": 'host.autonomous_system.organization:"China Education and Research Network"'},
        {"field": "host.services.software.product", "label": "产品", "example": 'host.services.software.product:"nginx"'},
    ],
}

# 各引擎已知字段（用于未知字段提示；缺失时提示核对，不阻断）
_KNOWN_FIELDS: dict[str, set[str]] = {
    "fofa": {
        "title", "body", "domain", "host", "ip", "port", "protocol", "server",
        "country", "city", "region", "org", "cert", "cert.subject",
        "cert.subject.cn", "cert.subject.org", "cert.issuer", "cert.issuer.org",
        "header", "banner", "app", "os", "icon_hash", "icp", "base_protocol",
        "status_code", "type", "after", "before", "size",
    },
    "quake": {
        "title", "body", "domain", "hostname", "ip", "port", "protocol",
        "service.name", "server", "country", "city", "org", "app", "os",
        "cert", "favicon", "icp", "transport", "headers", "location", "response",
    },
    "hunter": {
        "web.title", "web.body", "web.app", "web.icon", "web.status_code",
        "web.similar", "web.tag", "domain.suffix", "ip.country", "ip.province",
        "ip.city", "ip.isp", "ip.os", "ip.hostname", "ip.company", "ip.tag",
        "header.status_code", "header.server", "header.content_type",
        "cert.subject_org", "cert.is_trust", "icp.number", "is_web",
        "port", "protocol",
    },
    "zoomeye": {
        "title", "body", "domain", "hostname", "ip", "port", "protocol",
        "service", "server", "country", "city", "org", "app", "header",
        "os", "ssl", "iconhash", "banner",
    },
    "shodan": {
        "http.title", "http.html", "http.favicon", "http.component",
        "ssl.cert", "product", "os", "net", "hostname", "port", "org",
        "country", "city", "http.status", "http.server",
    },
    "censys": {
        "host.services.http.response.html_title",
        "host.services.http.response.body",
        "host.dns.names", "host.ip", "host.services.port",
        "host.autonomous_system.organization", "host.services.protocol",
        "host.services.software.product", "host.location.country",
        "host.location.city", "host.operating_system.product",
        "host.services.http.response.headers",
        "host.services.http.response.status_code",
    },
}

# 字段 → 关键词类别
_FIELD_CATEGORY = {
    "domain": "domain", "host": "domain", "hostname": "domain",
    "domain.suffix": "domain", "host.dns.names": "domain",
    "title": "title", "web.title": "title", "http.title": "title",
    "host.services.http.response.html_title": "title",
    "org": "org", "cert.subject.org": "org", "cert.issuer.org": "org",
    "ip.company": "org", "host.autonomous_system.organization": "org",
    "ip": "ip", "host.ip": "ip", "net": "ip",
    "port": "port", "host.services.port": "port",
    "app": "app", "server": "app", "product": "app", "web.app": "app",
    "host.services.software.product": "app",
    "cert": "cert", "cert.subject": "cert", "cert.subject.cn": "cert",
    "ssl": "cert", "ssl.cert": "cert", "icon_hash": "cert", "iconhash": "cert",
    "favicon": "cert", "web.icon": "cert", "http.favicon": "cert",
}

_CATEGORY_LABELS = {
    "domain": "域名", "title": "标题", "org": "组织", "ip": "IP",
    "port": "端口", "app": "应用", "cert": "证书/图标", "text": "文本",
}


def _balance_issues(query: str) -> list[str]:
    issues: list[str] = []
    if query.count("(") != query.count(")"):
        issues.append("括号不匹配：左右括号数量不一致")
    if query.count('"') % 2 != 0:
        issues.append('双引号未闭合：引号数量为奇数')
    if query.count("'") % 2 != 0:
        issues.append("单引号未闭合：引号数量为奇数")
    return issues


def _collect_tokens(query: str) -> tuple[list[dict[str, str]], list[str], str]:
    """合并解析 FOFA 风格与冒号风格条件。

    返回 (tokens, joins, style)；style ∈ fofa / colon / mixed / none。
    """
    fofa_tokens, joins = parse_fofa_query(query)
    colon_tokens: list[dict[str, str]] = []
    for m in _COLON_TOKEN_RE.finditer(query):
        raw_val = m.group(2)
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (
            raw_val.startswith("'") and raw_val.endswith("'")
        ):
            value = raw_val[1:-1].replace(r"\"", '"').replace(r"\'", "'").replace(r"\\", "\\")
        else:
            value = raw_val
        colon_tokens.append({
            "field": m.group(1).lower().strip(),
            "op": ":",
            "value": value,
        })

    if fofa_tokens and colon_tokens:
        style = "mixed"
    elif fofa_tokens:
        style = "fofa"
    elif colon_tokens:
        style = "colon"
    else:
        style = "none"
    return fofa_tokens + colon_tokens, joins, style


def _syntax_mismatch(engine: str, style: str) -> str:
    """查询写法与当前引擎语法风格不一致时给出提示（空串表示无问题）。"""
    style_info = _ENGINE_STYLE.get(engine, _ENGINE_STYLE["fofa"])
    if style == "mixed":
        return "查询混用了 = 与 : 两种写法，建议统一成当前引擎语法"
    if style == "fofa" and style_info["joiner"] == ":":
        return (
            f"当前引擎 {style_info['label']} 用 field:value（冒号）连接，"
            f"而查询是 FOFA 的 field=\"value\"（等号），注意核对语法"
        )
    if style == "colon" and style_info["joiner"] == "=":
        return (
            f"当前引擎 {style_info['label']} 用 field=\"value\"（等号）连接，"
            f"而查询是 field:value（冒号），注意核对语法"
        )
    return ""


def analyze_query(engine: str, query: str, src_type: str = "edusrc", intent_mode: str = "") -> dict:
    """解析查询条件，返回统计 / 关键词 / 问题提示 / 字段速查 / 一句话描述（不落库）。"""
    q = (query or "").strip()
    eng = (engine or "").strip().lower() or "fofa"
    style_info = _ENGINE_STYLE.get(eng, _ENGINE_STYLE["fofa"])
    empty = {
        "looks_like_syntax": False, "token_count": 0, "joins": [],
        "fields": [], "keywords": {}, "issues": [], "summary": "",
        "engine_hint": style_info["hint"], "syntax_mismatch": "",
        "field_sheet": _FIELD_SHEET.get(eng, _FIELD_SHEET["fofa"]),
        "tokens_detail": [],
    }
    if not q:
        return empty

    tokens, joins, style = _collect_tokens(q)
    known = _KNOWN_FIELDS.get(eng, _KNOWN_FIELDS["fofa"])

    issues = _balance_issues(q)
    mismatch = _syntax_mismatch(eng, style)
    if mismatch:
        issues.append(mismatch)
    fields: list[str] = []
    keywords: dict[str, list[str]] = {}
    for t in tokens:
        f = t["field"]
        if f not in fields:
            fields.append(f)
        if f not in known:
            msg = f"字段 {f} 可能不是 {eng} 的官方字段，注意核对语法"
            if msg not in issues:
                issues.append(msg)
        cat = _FIELD_CATEGORY.get(f, "text")
        v = t["value"].strip()
        if not v:
            continue
        if cat == "domain":
            v = v.lstrip(".")
        bucket = keywords.setdefault(cat, [])
        if v not in bucket:
            bucket.append(v)

    looks_syntax = bool(tokens)

    if intent_mode == "intent":
        summary = "意图模式：交给搜集 Agent 翻译成语法，并按结果逐轮演化"
    elif looks_syntax:
        parts: list[str] = []
        for cat in ("domain", "title", "org", "ip", "port", "app", "cert", "text"):
            vals = keywords.get(cat)
            if vals:
                parts.append(f"{_CATEGORY_LABELS[cat]} {('、'.join(vals[:3]))}")
        if parts:
            summary = f"按{' + '.join(parts)} 搜索，共 {len(tokens)} 个条件"
        else:
            summary = f"识别到 {len(tokens)} 个语法条件"
    else:
        summary = "未识别到语法条件，看起来是一段自然语言意图"

    return {
        "looks_like_syntax": looks_syntax,
        "token_count": len(tokens),
        "joins": joins,
        "fields": fields,
        "keywords": keywords,
        "issues": issues,
        "summary": summary,
        "engine_hint": style_info["hint"],
        "syntax_mismatch": mismatch,
        "field_sheet": _FIELD_SHEET.get(eng, _FIELD_SHEET["fofa"]),
        "tokens_detail": tokens,
    }
