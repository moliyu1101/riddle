"""侦察能力补强（阶段一）：资产发现 + 指纹识别与已知漏洞匹配。

解决两个短板：
1. 手动清单只给根域时攻击面不足 → asset_discovery（子域 / 高价值路径 / 同 IP 资产）。
2. 组件漏洞靠运气 → fingerprint（系统 / 中间件 / 框架 / WAF / 版本识别 + 已知漏洞匹配）。

安全约束：
- 全部只读：子域 = 测绘引擎查询 / DNS 解析；路径 = 只读 GET；同 IP = 引擎查询 / TCP connect。
- 短超时、小规模、并发受限，绝不触碰数据、不做破坏性操作。
- 已知漏洞匹配只给「验证思路」，不自动打；实证仍走 http_request。
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from app.agents.intel import detect_fingerprints
from app.tools.verify_chain import render_verify_plan
from app.tools.waf_advisor import _detect_waf, _normalize_headers as _norm_waf_headers

# ============ 常量 ============
# 高价值路径字典（后台 / 认证 / API 文档 / 监控 / 配置 / 上传 / 导出 / 备份 / 源码泄露）。
# 只放 SRC 场景有复用价值的端点，宁缺毋滥。
_HIGH_VALUE_PATHS: list[tuple[str, str]] = [
    # (path, value)
    ("/admin", "admin"), ("/admin/", "admin"), ("/administrator", "admin"),
    ("/manage", "admin"), ("/manager", "admin"), ("/system", "admin"),
    ("/system/", "admin"), ("/login", "auth"), ("/login.jsp", "auth"),
    ("/user/login", "auth"), ("/api/login", "auth"),
    ("/api", "api"), ("/api/", "api"),
    ("/swagger-ui.html", "api_doc"), ("/swagger-ui/index.html", "api_doc"),
    ("/v2/api-docs", "api_doc"), ("/v3/api-docs", "api_doc"),
    ("/openapi.json", "api_doc"),
    ("/actuator", "monitor"), ("/actuator/env", "monitor"),
    ("/actuator/health", "monitor"), ("/actuator/heapdump", "monitor"),
    ("/druid/index.html", "monitor"), ("/druid/", "monitor"),
    ("/nacos/", "monitor"), ("/console", "console"),
    ("/jmx-console", "console"), ("/manager/html", "console"),
    ("/status", "status"), ("/server-status", "status"),
    ("/config", "config"), ("/config/", "config"),
    ("/web.config", "config"), ("/.env", "config"),
    ("/application.yml", "config"), ("/application.properties", "config"),
    ("/upload", "upload"), ("/upload/", "upload"), ("/uploads", "upload"),
    ("/file/upload", "upload"), ("/ueditor/", "upload"),
    ("/export", "export"), ("/export/", "export"),
    ("/download", "export"), ("/download/", "export"),
    ("/.git/", "source"), ("/.git/config", "source"),
    ("/.svn/", "source"), ("/.DS_Store", "source"),
    ("/backup", "backup"), ("/backup/", "backup"), ("/bak", "backup"),
    ("/www.zip", "backup"), ("/web.zip", "backup"),
    ("/phpinfo.php", "info"), ("/info.php", "info"), ("/test.php", "info"),
]

# 常见子域前缀（教育 / 企业高频），DNS 回退枚举用。
_SUBDOMAIN_PREFIXES = [
    "www", "mail", "vpn", "webvpn", "oa", "portal", "sso", "cas", "idp",
    "api", "admin", "test", "dev", "ftp", "lib", "library", "jw", "jwc",
    "jwsystem", "ehall", "xg", "xsc", "news", "bbs", "blog", "m", "mobile",
    "app", "cloud", "crm", "erp", "hr", "old", "new", "static", "img",
    "cdn", "download", "file", "files", "data", "db", "monitor", "status",
    "git", "jenkins", "nacos", "kibana", "grafana", "zabbix", "wiki",
    "docs", "help", "support", "service", "web", "wap", "study", "teach",
    "course", "exam", "score", "pay", "finance", "card",
]

# 同 IP 资产回退探测的常见端口（TCP connect 只探开放，不碰服务）。
_COMMON_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 7001, 7002,
    9200, 9300, 3306, 6379, 5432, 1433, 27017, 11211, 8161,
    22, 21, 23, 3389, 5900, 8009, 8081, 8082, 5000, 5001, 3000,
]

# 结果上限
_MAX_SUBDOMAIN = 40
_MAX_PATHS = 40
_MAX_SAME_IP = 40
_MAX_VULNS = 8

# 网络参数
_PROBE_TIMEOUT = 5.0
_DNS_TIMEOUT = 3.0
_TCP_TIMEOUT = 2.0
_PATH_WORKERS = 8
_DNS_WORKERS = 16

# ============ 纯逻辑：目标归一化 / 根域提取 ============
def _normalize_target(target: str) -> Optional[dict[str, Any]]:
    """把 'example.com' / 'https://example.com:8080/x' 归一化成 {host, port, scheme, base}。"""
    t = (target or "").strip()
    if not t:
        return None
    if "://" not in t:
        t = "http://" + t
    try:
        u = urlparse(t)
    except Exception:
        return None
    host = (u.hostname or "").strip().lower()
    if not host:
        return None
    scheme = (u.scheme or "http").lower()
    port = u.port
    base = f"{scheme}://{host}" + (f":{port}" if port else "")
    return {"host": host, "port": port, "scheme": scheme, "base": base}


def _root_domain(host: str) -> str:
    """提取可注册根域：xxx.edu.cn 取后三段，其余取后两段。"""
    host = (host or "").strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts) >= 3 and parts[-2] == "edu" and parts[-1] == "cn":
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _safe_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"<[^>]+>", "", m.group(1)).strip()[:120]


# ============ 纯逻辑：路径命中分类 ============
# 命中后按「价值标签」排序，高价值（源码/配置/监控/上传）排前面。
_PATH_VALUE_ORDER = {
    "source": 0, "config": 1, "monitor": 2, "upload": 3,
    "api_doc": 4, "admin": 5, "auth": 6, "backup": 7,
    "export": 8, "console": 9, "info": 10, "api": 11, "status": 12,
}
_PATH_VALUE_LABEL = {
    "source": "源码/版本控制泄露", "config": "配置文件泄露", "monitor": "监控/管理端点",
    "upload": "上传接口", "api_doc": "API 文档", "admin": "后台入口", "auth": "登录入口",
    "backup": "备份文件", "export": "导出/下载", "console": "控制台", "info": "信息探测",
    "api": "API 入口", "status": "状态页",
}
_PATH_HIT_KEYWORDS = {
    "source": (".git", ".svn", ".DS_Store"),
    "config": (".env", "web.config", "application.yml", "application.properties"),
    "monitor": ("actuator", "druid", "nacos"),
    "upload": ("upload", "ueditor"),
    "export": ("export", "download"),
    "backup": ("backup", "bak", ".zip"),
    "api_doc": ("swagger", "api-docs", "openapi"),
    "console": ("console", "manager/html", "jmx-console"),
    "info": ("phpinfo", "info.php", "test.php"),
}


def _classify_path(path: str, status: int, title: str, body: str) -> dict[str, Any]:
    """把单个路径探测结果分类成带价值标签的条目。"""
    low_body = (body or "").lower()
    low_title = (title or "").lower()
    blob = f"{path} {low_title} {low_body[:400]}"
    value = "api"
    for v, kws in _PATH_HIT_KEYWORDS.items():
        if any(k in blob for k in kws):
            value = v
            break
    evidence = ""
    if title:
        evidence = f"title={title[:60]}"
    elif status == 200 and body:
        # 200 但无 title：取 body 首行可辨识文本
        text = re.sub(r"<[^>]+>", " ", body)
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            evidence = f"body={text[:60]}"
    return {
        "path": path,
        "status": status,
        "value": value,
        "label": _PATH_VALUE_LABEL.get(value, value),
        "evidence": evidence,
    }


# ============ 纯逻辑：组件 / 版本 / WAF 识别 ============
_COMPONENT_MARKERS: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = [
    # (name, category, body_keywords, header_keywords)
    # header_keywords 匹配「全部响应头键+值拼成的小写串」，避免 Server 头存在就误判所有 server 组件。
    ("nginx", "server", ("nginx",), ("nginx",)),
    ("apache", "server", ("apache",), ("apache",)),
    ("iis", "server", ("iis", "microsoft-iis"), ("iis", "microsoft-iis")),
    ("tomcat", "server", ("tomcat", "apache tomcat"), ("tomcat",)),
    ("weblogic", "server", ("weblogic", "bea"), ("weblogic",)),
    ("jetty", "server", ("jetty",), ("jetty",)),
    ("openresty", "server", ("openresty",), ("openresty",)),
    ("caddy", "server", ("caddy",), ("caddy",)),
    ("gunicorn", "server", ("gunicorn",), ("gunicorn",)),
    ("uvicorn", "server", ("uvicorn",), ("uvicorn",)),
    ("kestrel", "server", ("kestrel",), ("kestrel",)),
    ("cloudflare", "waf", ("cloudflare", "cf-ray", "just a moment"), ("cloudflare", "cf-ray")),
    ("php", "language", ("php", "x-powered-by: php"), ("php",)),
    ("asp.net", "language", ("asp.net", "aspnet", "x-aspnet-version"), ("asp.net", "aspnet")),
    ("java", "language", ("java", "jsessionid", ".jsp", "servlet"), ("java",)),
    ("python", "language", ("python", "django", "flask", "fastapi", "uvicorn", "gunicorn", "werkzeug"), ("python", "django", "flask", "fastapi", "uvicorn", "gunicorn", "werkzeug")),
    ("nodejs", "language", ("node.js", "nodejs", "express", "koa", "next.js", "nuxt"), ("node.js", "nodejs", "express")),
    ("go", "language", ("golang", "go1.", "gin", "beego"), ("golang", "go1.")),
    ("thinkphp", "framework", ("thinkphp", "think_template"), ("thinkphp",)),
    ("laravel", "framework", ("laravel",), ("laravel",)),
    ("spring", "framework", ("spring", "whitelabel error page"), ("spring",)),
    ("springboot", "framework", ("springboot", "spring boot", "/actuator", "whitelabel error page"), ("springboot",)),
    ("shiro", "framework", ("shiro", "rememberme=deleteme"), ("shiro",)),
    ("struts2", "framework", ("struts2", "org.apache.struts2"), ("struts2",)),
    ("django", "framework", ("django", "csrftoken"), ("django",)),
    ("flask", "framework", ("flask", "werkzeug"), ("flask", "werkzeug")),
    ("fastapi", "framework", ("fastapi", "uvicorn"), ("fastapi",)),
    ("express", "framework", ("express", "x-powered-by: express"), ("express",)),
    ("ruoyi", "framework", ("若依", "ruoyi", "ry-"), ("ruoyi",)),
    ("fastjson", "component", ("fastjson", "com.alibaba.fastjson"), ("fastjson",)),
    ("log4j", "component", ("log4j", "log4j2"), ("log4j",)),
    ("jenkins", "system", ("jenkins", "x-jenkins"), ("jenkins",)),
    ("gitlab", "system", ("gitlab", "gitlab-ci"), ("gitlab",)),
    ("nacos", "system", ("nacos",), ("nacos",)),
    ("druid", "system", ("druid", "/druid/"), ("druid",)),
    ("swagger", "system", ("swagger", "swagger-ui"), ("swagger",)),
    ("grafana", "system", ("grafana",), ("grafana",)),
    ("kibana", "system", ("kibana",), ("kibana",)),
    ("phpmyadmin", "system", ("phpmyadmin",), ("phpmyadmin",)),
    ("coremail", "system", ("coremail",), ("coremail",)),
    ("exchange", "system", ("exchange", "owa"), ("exchange",)),
    ("seeyon", "oa", ("致远", "seeyon", "/seeyon/"), ("seeyon",)),
    ("weaver", "oa", ("泛微", "weaver", "/weaver/", "ecology"), ("weaver",)),
    ("tongda", "oa", ("通达", "tongda", "/ispirit/"), ("tongda",)),
    ("zhengfang", "edu", ("正方", "zfsoft", "/jwglxt/"), ("zfsoft",)),
    ("qiangzhi", "edu", ("强智", "jwgl", "教务系统"), ("jwgl",)),
    ("sangfor", "vpn", ("深信服", "sangfor", "/por/login"), ("sangfor",)),
    ("webvpn", "vpn", ("webvpn",), ("webvpn",)),
    ("cisco_vpn", "vpn", ("sslvpn", "cisco", "anyconnect"), ("sslvpn", "cisco")),
    ("wordpress", "cms", ("wordpress", "wp-content"), ("wordpress",)),
    ("drupal", "cms", ("drupal",), ("drupal",)),
    ("joomla", "cms", ("joomla",), ("joomla",)),
    ("elasticsearch", "db", ("cluster_name", "lucene_version", "you know, for search", "elasticsearch"), ("elasticsearch",)),
    ("solr", "system", ("solr", "solr-admin", "/solr/"), ("solr",)),
    ("zabbix", "system", ("zabbix", "/zabbix/"), ("zabbix",)),
]

_VERSION_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._-]*?)/(\d+\.\d+(?:\.\d+)*)\b")


def _detect_components(headers: dict[str, str], body: str) -> list[dict[str, str]]:
    """从响应头 + body 识别组件/框架/系统，返回 [{name, category, evidence}]。"""
    low_body = (body or "").lower()
    header_blob = " ".join(f"{k} {v}" for k, v in headers.items()).lower()
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for name, category, body_kws, header_kws in _COMPONENT_MARKERS:
        if name in seen:
            continue
        evidence = ""
        for kw in header_kws:
            if kw in header_blob:
                evidence = f"header 含 `{kw}`"
                break
        if not evidence:
            for kw in body_kws:
                if kw in low_body:
                    evidence = f"body 含 `{kw}`"
                    break
        if evidence:
            seen.add(name)
            out.append({"name": name, "category": category, "evidence": evidence})
    return out


def _extract_versions(headers: dict[str, str], body: str) -> list[dict[str, str]]:
    """从响应头/body 提取组件版本号，如 nginx/1.18.0、PHP/7.4.3。"""
    blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    blob += " " + (body or "")[:4000]
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in _VERSION_RE.finditer(blob):
        comp, ver = m.group(1).lower(), m.group(2)
        key = f"{comp}/{ver}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"component": comp, "version": ver})
    return out[:12]


# ============ 纯逻辑：已知漏洞匹配 ============
# match 命中组件名或 intel 指纹标识；只给验证思路，不自动打。
_KNOWN_VULNS: list[dict[str, Any]] = [
    {"match": ("thinkphp", "framework_thinkphp"), "cve": "CVE-2018-1002015",
     "name": "ThinkPHP 5.x 远程代码执行", "risk": "高危",
     "verify": "GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1 看是否回显 phpinfo；或 POST 构造 RCE payload 实证"},
    {"match": ("shiro", "framework_shiro"), "cve": "CVE-2016-4437",
     "name": "Apache Shiro 反序列化（Shiro-550）", "risk": "高危",
     "verify": "登录响应 Set-Cookie 含 rememberMe=deleteMe 即存在；用 rememberMe cookie 打反序列化 gadget 验证 RCE"},
    {"match": ("springboot", "framework_springboot"), "cve": "-",
     "name": "Spring Boot Actuator 未授权访问", "risk": "中危",
     "verify": "GET /actuator/env、/actuator/heapdump、/actuator/mappings 看是否未授权返回配置/内存/路由"},
    {"match": ("spring",), "cve": "CVE-2022-22965",
     "name": "Spring Framework RCE（Spring4Shell）", "risk": "高危",
     "verify": "对 SpringMVC 参数绑定打 class.module.classLoader 链验证"},
    {"match": ("nacos", "mw_nacos"), "cve": "CVE-2021-29441",
     "name": "Nacos 认证绕过", "risk": "高危",
     "verify": "GET /nacos/v1/auth/users?pageNo=1&pageSize=9 未授权列用户；或 /nacos/v1/cs/configs 未授权读配置"},
    {"match": ("druid", "mw_druid"), "cve": "-",
     "name": "Druid 监控未授权访问", "risk": "中危",
     "verify": "GET /druid/index.html 未授权可看 SQL/会话/URI 监控"},
    {"match": ("swagger", "api_swagger"), "cve": "-",
     "name": "Swagger/API 文档未授权", "risk": "低危",
     "verify": "GET /swagger-ui.html、/v2/api-docs 未授权可枚举全部接口"},
    {"match": ("grafana", "mw_grafana"), "cve": "CVE-2021-43798",
     "name": "Grafana 任意文件读取", "risk": "高危",
     "verify": "GET /public/plugins/alertlist/../../../../../../../../etc/passwd 看是否回显"},
    {"match": ("kibana", "mw_kibana"), "cve": "CVE-2019-7609",
     "name": "Kibana 远程代码执行", "risk": "高危",
     "verify": "Kibana <6.6.0 用 Timelion prototype pollution 打 RCE"},
    {"match": ("phpmyadmin", "db_phpmyadmin"), "cve": "CVE-2018-12613",
     "name": "phpMyAdmin 本地文件包含", "risk": "高危",
     "verify": "GET /index.php?target=db_sql.php%253f/../../../../etc/passwd 验证"},
    {"match": ("coremail", "mail_coremail"), "cve": "-",
     "name": "Coremail 配置信息泄露", "risk": "中危",
     "verify": "访问 /coremail/ 相关配置/日志端点看是否泄露 SMTP 凭据"},
    {"match": ("seeyon", "oa_seeyon"), "cve": "CNVD-2021-01627",
     "name": "致远 A8 任意文件上传/未授权", "risk": "严重",
     "verify": "致远 A8 历史文件上传/任意文件读取端点验证（如 /seeyon/htmlofficeservlet）"},
    {"match": ("weaver", "oa_weaver"), "cve": "CNVD-2019-32204",
     "name": "泛微 e-cology SQL 注入/文件上传", "risk": "高危",
     "verify": "泛微 OA 历史 SQL 注入/文件上传端点验证"},
    {"match": ("tongda", "oa_tongda"), "cve": "-",
     "name": "通达 OA 任意文件上传/包含", "risk": "高危",
     "verify": "通达 OA /ispirit/ 系列文件上传/包含端点验证"},
    {"match": ("ruoyi", "framework_ruoyi"), "cve": "-",
     "name": "RuoYi 若依 定时任务/接口未授权", "risk": "中危",
     "verify": "RuoYi 默认 /prod-api/ 未授权接口、定时任务 RCE 端点验证"},
    {"match": ("weblogic",), "cve": "CVE-2020-14882",
     "name": "WebLogic 未授权远程代码执行", "risk": "严重",
     "verify": "GET /console/css/%252e%252e%252fconsole.portal 未授权访问管理控制台验证"},
    {"match": ("tomcat",), "cve": "CVE-2020-1938",
     "name": "Apache Tomcat AJP 文件读取（Ghostcat）", "risk": "高危",
     "verify": "8009 AJP 端口用 Ghostcat 读 WEB-INF/web.xml；或 CVE-2017-12615 PUT 上传验证"},
    {"match": ("apache",), "cve": "CVE-2021-41773",
     "name": "Apache HTTP Server 路径穿越 RCE", "risk": "高危",
     "verify": "GET /cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd（2.4.49/2.4.50）验证"},
    {"match": ("nginx",), "cve": "CVE-2017-7529",
     "name": "Nginx 整数溢出信息泄露", "risk": "低危",
     "verify": "旧版 nginx Range 头整数溢出读缓存文件"},
    {"match": ("jenkins",), "cve": "-",
     "name": "Jenkins 未授权/脚本控制台", "risk": "高危",
     "verify": "GET /script 未授权 Groovy 脚本控制台验证"},
    {"match": ("gitlab",), "cve": "CVE-2021-22205",
     "name": "GitLab 未授权 RCE", "risk": "严重",
     "verify": "GitLab <13.10.3 ExifTool 上传 RCE 验证"},
    {"match": ("fastjson",), "cve": "CVE-2017-18349",
     "name": "Fastjson 反序列化 RCE", "risk": "严重",
     "verify": "POST JSON 带 @type 反序列化 payload 验证（1.2.24 及多版本绕过）"},
    {"match": ("log4j",), "cve": "CVE-2021-44228",
     "name": "Log4j2 JNDI 注入 RCE", "risk": "严重",
     "verify": "可控参数注入 ${jndi:ldap://...} 触发 DNS/回连验证"},
    {"match": ("struts2",), "cve": "CVE-2017-5638",
     "name": "Struts2 远程代码执行（S2-045）", "risk": "严重",
     "verify": "Content-Type 头注入 OGNL payload 验证"},
    {"match": ("wordpress",), "cve": "-",
     "name": "WordPress 插件/主题已知漏洞", "risk": "中危",
     "verify": "识别插件版本后匹配已知 CVE；wp-json 未授权枚举用户"},
    {"match": ("sangfor", "vpn_sangfor"), "cve": "-",
     "name": "深信服 SSL VPN 未授权访问", "risk": "严重",
     "verify": "深信服 SSL VPN 历史未授权 RCE/信息泄露端点验证"},
    {"match": ("webvpn", "vpn_webvpn"), "cve": "-",
     "name": "WebVPN 未授权/信息泄露", "risk": "中危",
     "verify": "WebVPN 历史未授权访问内部资源端点验证"},
    {"match": ("elasticsearch", "db_elasticsearch"), "cve": "-",
     "name": "Elasticsearch 未授权访问", "risk": "高危",
     "verify": "GET / 未授权返回集群信息含 cluster_name/version；GET /_cat/indices 列全部索引及文档数"},
    {"match": ("solr", "mw_solr"), "cve": "CVE-2019-17558",
     "name": "Apache Solr 远程代码执行", "risk": "高危",
     "verify": "GET /solr/admin/ 未授权管理页；CVE-2019-17558 利用 Velocity 模板注入 RCE"},
    {"match": ("zabbix", "mw_zabbix"), "cve": "-",
     "name": "Zabbix 未授权访问", "risk": "中危",
     "verify": "GET /zabbix/ 未授权访问监控面板；/api_jsonrpc.php 未授权调用 API 枚举主机/项目"},
]


def _match_known_vulns(components: list[dict[str, str]], fingerprints: list[str]) -> list[dict[str, Any]]:
    """按识别出的组件/指纹匹配内置已知漏洞表，限量返回。"""
    names = {c["name"] for c in components}
    names.update(fingerprints)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for v in _KNOWN_VULNS:
        hit = next((m for m in v["match"] if m in names), None)
        if not hit:
            continue
        key = v["name"]
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "cve": v["cve"],
            "name": v["name"],
            "risk": v["risk"],
            "verify": v["verify"],
            "matched_by": hit,
        })
        if len(out) >= _MAX_VULNS:
            break
    return out


# ============ 网络辅助 ============
def _make_client(timeout: float = _PROBE_TIMEOUT) -> httpx.Client:
    return httpx.Client(
        verify=False,
        timeout=timeout,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
    )


def _http_get(client: httpx.Client, url: str, timeout: float = _PROBE_TIMEOUT) -> tuple[int, dict[str, str], str]:
    """只读 GET，返回 (status, headers, body)。任何异常降级为 (0, {}, '')。"""
    try:
        resp = client.get(url, timeout=timeout, follow_redirects=True)
        body = resp.text[:200_000]
        return resp.status_code, dict(resp.headers), body
    except Exception:
        return 0, {}, ""


def _dns_resolve(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return sorted({info[4][0] for info in infos})
    except Exception:
        return []


def _tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=_TCP_TIMEOUT):
            return True
    except Exception:
        return False


# ============ 资产发现 ============
def discover_subdomains(
    domain: str,
    *,
    engine: str = "fofa",
    api_key: str = "",
    base_url: str = "",
    client: Optional[httpx.Client] = None,
    max_results: int = _MAX_SUBDOMAIN,
) -> dict[str, Any]:
    """子域枚举：优先测绘引擎（domain= 查询），无 key 时回退 DNS 前缀枚举。"""
    root = _root_domain(domain)
    results: list[dict[str, Any]] = []
    source = ""
    own_client = client is None
    if not client:
        client = _make_client()

    try:
        # 1) 测绘引擎优先
        if api_key:
            try:
                from app.engines.sync import engine_search_sync, result_rows_to_dicts

                res = engine_search_sync(
                    engine, api_key, f'domain="{root}"',
                    page=1, page_size=max_results, base_url=base_url or None,
                )
                seen: set[str] = set()
                for r in result_rows_to_dicts(res, limit=max_results):
                    host = (r.get("host") or "").strip().lower()
                    if not host or host in seen:
                        continue
                    seen.add(host)
                    results.append({
                        "host": host,
                        "ip": r.get("ip", ""),
                        "title": (r.get("title", "") or "")[:120],
                        "source": "engine",
                    })
                source = f"engine:{engine}"
            except Exception:
                pass

        # 2) 引擎没出结果 → DNS 前缀枚举
        if not results:
            source = "dns"
            candidates = [f"{p}.{root}" for p in _SUBDOMAIN_PREFIXES] + [root]
            resolved: dict[str, list[str]] = {}
            with ThreadPoolExecutor(max_workers=_DNS_WORKERS) as pool:
                futs = {pool.submit(_dns_resolve, c): c for c in candidates}
                for fut in as_completed(futs, timeout=_DNS_TIMEOUT * 4 + 5):
                    c = futs[fut]
                    try:
                        ips = fut.result()
                    except Exception:
                        ips = []
                    if ips:
                        resolved[c] = ips
            # 对解析成功的子域做一次 HTTP 探测拿 title（并行、短超时）
            hosts = sorted(resolved.keys())
            titles: dict[str, str] = {}
            with ThreadPoolExecutor(max_workers=_DNS_WORKERS) as pool:
                futs = {
                    pool.submit(_http_get, client, f"http://{h}", 3.0): h
                    for h in hosts
                }
                for fut in as_completed(futs, timeout=20):
                    h = futs[fut]
                    try:
                        status, _, body = fut.result()
                        if status:
                            titles[h] = _safe_title(body)
                    except Exception:
                        pass
            for h in hosts:
                ips = resolved.get(h, [])
                results.append({
                    "host": h,
                    "ip": ",".join(ips[:3]),
                    "title": titles.get(h, ""),
                    "source": "dns",
                })
    finally:
        if own_client:
            try:
                client.close()
            except Exception:
                pass

    results = results[:max_results]
    return {
        "ok": True,
        "enum_type": "subdomain",
        "root_domain": root,
        "source": source,
        "total": len(results),
        "results": results,
        "guidance": (
            "子域即攻击面：优先挑 title 含后台/管理/API/门户/教务/邮箱的入口深入；"
            "对每个子域用 http_request 实证归属与可达性，再决定是否单独挖。"
        ),
    }


def enumerate_paths(
    base_url: str,
    *,
    client: Optional[httpx.Client] = None,
    max_results: int = _MAX_PATHS,
) -> dict[str, Any]:
    """高价值路径枚举：只读 GET 探测敏感端点，按价值标签排序。"""
    own_client = client is None
    if not client:
        client = _make_client()
    hits: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=_PATH_WORKERS) as pool:
            futs = {
                pool.submit(_http_get, client, base_url + path, _PROBE_TIMEOUT): path
                for path, _ in _HIGH_VALUE_PATHS
            }
            for fut in as_completed(futs, timeout=_PROBE_TIMEOUT * 2 + 10):
                path = futs[fut]
                try:
                    status, _, body = fut.result()
                except Exception:
                    continue
                if status in (0, 404, 400, 405):
                    continue
                title = _safe_title(body)
                hits.append(_classify_path(path, status, title, body))
    finally:
        if own_client:
            try:
                client.close()
            except Exception:
                pass

    hits.sort(key=lambda x: (_PATH_VALUE_ORDER.get(x["value"], 99), x["path"]))
    hits = hits[:max_results]
    return {
        "ok": True,
        "enum_type": "path",
        "base_url": base_url,
        "total": len(hits),
        "results": hits,
        "guidance": (
            "按价值标签优先验证：源码/配置/监控/上传类命中直接用 http_request 实证"
            "（如 .git/config 是否可读、actuator/env 是否未授权、swagger 是否可枚举接口）。"
            "只读验证，不碰数据。"
        ),
    }


def discover_same_ip(
    host: str,
    *,
    engine: str = "fofa",
    api_key: str = "",
    base_url: str = "",
    max_results: int = _MAX_SAME_IP,
) -> dict[str, Any]:
    """同 IP 资产发现：解析目标 IP → 引擎查 ip= 看同 IP 其它服务；无 key 时 TCP 端口探测。"""
    ips = _dns_resolve(host)
    if not ips:
        return {"ok": False, "error": f"无法解析 {host} 的 IP，跳过同 IP 资产发现。"}
    ip = ips[0]
    results: list[dict[str, Any]] = []
    source = ""

    # 1) 测绘引擎优先
    if api_key:
        try:
            from app.engines.sync import engine_search_sync, result_rows_to_dicts

            res = engine_search_sync(
                engine, api_key, f'ip="{ip}"',
                page=1, page_size=max_results, base_url=base_url or None,
            )
            seen: set[str] = set()
            for r in result_rows_to_dicts(res, limit=max_results):
                key = f"{r.get('host','')}:{r.get('port','')}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "host": r.get("host", ""),
                    "port": r.get("port", ""),
                    "protocol": r.get("protocol", ""),
                    "title": (r.get("title", "") or "")[:120],
                    "source": "engine",
                })
            source = f"engine:{engine}"
        except Exception:
            pass

    # 2) 无引擎结果 → TCP 端口探测
    if not results:
        source = "tcp"
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = {pool.submit(_tcp_open, ip, p): p for p in _COMMON_PORTS}
            for fut in as_completed(futs, timeout=_TCP_TIMEOUT * 2 + 5):
                p = futs[fut]
                try:
                    if fut.result():
                        open_ports.append(p)
                except Exception:
                    pass
        for p in sorted(open_ports):
            proto = "https" if p in (443, 8443) else ("http" if p in (80, 8080, 8000, 8888, 9000) else "tcp")
            results.append({"host": ip, "port": str(p), "protocol": proto, "title": "", "source": "tcp"})

    results = results[:max_results]
    return {
        "ok": True,
        "enum_type": "same_ip",
        "ip": ip,
        "source": source,
        "total": len(results),
        "results": results,
        "guidance": (
            "同 IP 其它端口/服务可能是同一单位资产：优先看 8080/8443/7001/9200/8161 等"
            "中间件/管理端口，用 http_request 确认归属后单独验证；注意先确认是否在授权范围。"
        ),
    }


def asset_discovery(
    target: str,
    enum_type: str = "subdomain",
    *,
    engine: str = "fofa",
    api_key: str = "",
    base_url: str = "",
    client: Optional[httpx.Client] = None,
    max_results: int = 20,
) -> dict[str, Any]:
    """资产发现统一入口：subdomain / path / same_ip。"""
    norm = _normalize_target(target)
    if not norm:
        return {"ok": False, "kind": "arg_error", "error": "target 无法解析，需为域名或 URL。"}
    et = (enum_type or "subdomain").strip().lower()
    safe_max = max(1, min(int(max_results or 20), 40))
    try:
        if et == "path":
            return enumerate_paths(norm["base"], client=client, max_results=safe_max)
        if et == "same_ip":
            return discover_same_ip(
                norm["host"], engine=engine, api_key=api_key,
                base_url=base_url, max_results=safe_max,
            )
        # 默认 subdomain
        return discover_subdomains(
            norm["host"], engine=engine, api_key=api_key,
            base_url=base_url, client=client, max_results=safe_max,
        )
    except Exception as e:
        return {"ok": False, "error": f"资产发现异常: {type(e).__name__}: {e}"}


# ============ 指纹识别 + 已知漏洞匹配 ============
def fingerprint(
    url: str = "",
    headers: Optional[dict[str, Any]] = None,
    body: str = "",
    title: str = "",
    *,
    client: Optional[httpx.Client] = None,
) -> dict[str, Any]:
    """识别系统/中间件/框架/WAF/版本，并匹配内置已知漏洞表。

    传 url 自动发只读 GET 抓响应头/body；或直接传已拿到的 headers/body/title。
    纯本地匹配，只给验证思路，不自动打。
    """
    own_client = client is None
    if not client:
        client = _make_client()

    resp_url = ""
    try:
        if url and not headers and not body:
            status, hdrs, bd = _http_get(client, url)
            if status:
                headers, body, resp_url = hdrs, bd, url
                if not title:
                    title = _safe_title(bd)
        norm_headers = _norm_waf_headers(headers or {})
        low_body = (body or "").lower()

        # 1) 系统指纹（复用 intel 指纹库）
        fps = detect_fingerprints(title, " ".join(f"{k}: {v}" for k, v in (headers or {}).items()), body)

        # 2) 组件/框架
        components = _detect_components(norm_headers, body)

        # 3) 版本
        versions = _extract_versions(norm_headers, body)

        # 4) WAF
        waf_sig, waf_evidence = _detect_waf(0, norm_headers, body)
        waf = {"detected": waf_sig.name != "none", "type": waf_sig.name, "evidence": waf_evidence}

        # 5) 已知漏洞匹配
        vulns = _match_known_vulns(components, fps)
        # 自动生成可执行验证块：命中已知漏洞时给出具体探针，引导 worker 直接实测。
        verify_plan = render_verify_plan(vulns)

        return {
            "ok": True,
            "url": resp_url or url,
            "title": title,
            "system_fingerprints": fps,
            "components": components,
            "versions": versions,
            "waf": waf,
            "known_vulns": vulns,
            "verify_plan": verify_plan,
            "guidance": (
                "指纹只是线索地图。命中 known_vulns 时，优先按 verify_plan 里的探针用 "
                "verify_known_vuln(url, 漏洞名) 一键实测（只读/无害探针）；无探针的漏洞按 "
                "verify 思路用 http_request 实证。实证命中只代表组件/端点暴露，按实际危害"
                "确认后再 submit_finding；没实证危害不要交。"
                "识别出系统后，优先查情报库同款系统历史打法（编排层会自动注入）。"
            ),
        }
    except Exception as e:
        return {"ok": False, "error": f"指纹识别异常: {type(e).__name__}: {e}"}
    finally:
        if own_client:
            try:
                client.close()
            except Exception:
                pass
