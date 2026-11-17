"""写回范围守卫：在数据层拦住越界资产，补 Riddle 目前的空白。

现有 ``app/tools/netguard.py`` 管的是「带凭证的请求别打到内网/云元数据」，
``app/tools/guard.py`` 管的是「命令别自毁」，两者都不约束「worker 把一个
非本任务范围的资产写进 fact/finding」。本模块做三层分类：

  own     —— 本任务授权范围内的根域 / 网段，允许写回
  source  —— 任务显式声明的外部来源，只读共享，不允许写回新结论
  foreign —— 其余一切，直接拒绝写回

另加基础设施黑名单（云元数据、回环、链路本地、私网段），这类目标无论
是否在 scope 里都不允许写回，避免一次归属误判把整条链带偏。

默认只做判定与留痕，硬拦截由 ``FUSION_SCOPE_GUARD_HARD=1`` 开启。
"""
from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

OWN = "own"
SOURCE = "source"
FOREIGN = "foreign"
INFRA = "infra"

# 通用基础设施占位：不写任何具体厂商/品牌名，只列协议约定的地址与语义关键字
_INFRA_LITERALS = ("169.254.169.254", "metadata", "metadata.internal", "localhost", "127.0.0.1", "0.0.0.0", "::1")
_INFRA_HINTS = ("metadata", "instance-data", "latest/meta", "link-local")
# 常见二级公共后缀：取根域时多保留一段，避免把 a.com.cn 与 b.com.cn 判成同一根
_MULTI_PART_SUFFIXES = ("com.cn", "edu.cn", "org.cn", "net.cn", "gov.cn", "ac.cn", "co.uk", "org.uk", "com.hk", "com.tw")


def normalize_host(value: Any) -> str:
    """从 URL / host:port / 裸域名里取出小写主机名。"""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        try:
            raw = urlsplit(raw).hostname or ""
        except ValueError:
            raw = raw.split("://", 1)[-1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if raw.startswith("[") and "]" in raw:  # IPv6 字面量
        return raw[1:raw.index("]")]
    if raw.count(":") == 1:
        raw = raw.rsplit(":", 1)[0]
    return raw.strip(".")


def root_domain(host: str) -> str:
    """通用根域推导：不加任何品牌/机构名单。"""
    host = normalize_host(host)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    tail2 = ".".join(parts[-2:])
    if tail2 in _MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def is_infra(host: str) -> bool:
    h = normalize_host(host)
    if not h:
        return False
    if h in _INFRA_LITERALS or any(k in h for k in _INFRA_HINTS):
        return True
    try:
        addr = ipaddress.ip_address(h)
        return bool(addr.is_loopback or addr.is_link_local or addr.is_private or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def _in_cidrs(host: str, cidrs: list[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in cidrs or []:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def classify(value: Any, scope: dict | None = None) -> str:
    """返回 own / source / foreign / infra。"""
    host = normalize_host(value)
    if not host:
        return FOREIGN
    if is_infra(host):
        return INFRA
    scope = scope or {}
    roots = [root_domain(r) for r in (scope.get("roots") or []) if r]
    if root_domain(host) in roots:
        return OWN
    if _in_cidrs(host, scope.get("cidrs") or []):
        return OWN
    sources = [normalize_host(s) for s in (scope.get("sources") or []) if s]
    if any(host == s or host.endswith("." + root_domain(s)) for s in sources if s):
        return SOURCE
    return FOREIGN


def check_writeback(value: Any, scope: dict | None = None) -> dict:
    """判定一次 fact/finding 写回是否允许。纯函数。"""
    host = normalize_host(value)
    bucket = classify(host, scope)
    reasons = {
        OWN: "",
        SOURCE: "该资产来自外部只读共享来源，不允许在本任务写回新结论",
        FOREIGN: f"资产 {host or '(空)'} 不在本任务授权范围内，写回被拒绝",
        INFRA: "基础设施/内网/云元数据地址不允许写回",
    }
    return {
        "host": host,
        "classification": bucket,
        "allowed": bucket == OWN,
        "reason": reasons[bucket],
    }


def normalize_scope(raw: dict | None) -> dict:
    """把任务级范围配置收敛成内部结构，供 API 与测试复用。"""
    raw = raw or {}
    return {
        "roots": [normalize_host(x) for x in (raw.get("roots") or raw.get("domains") or []) if x],
        "sources": [normalize_host(x) for x in (raw.get("sources") or []) if x],
        "cidrs": [str(x) for x in (raw.get("cidrs") or raw.get("ips") or []) if x],
        "company": str(raw.get("company") or "").strip(),
    }
