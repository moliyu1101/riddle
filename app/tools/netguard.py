"""出站 URL 的 SSRF 校验。

仅用于 **知蠹 Riddle 自身携带凭证的配置探测请求**（如拉取模型商 /models 列表、
FOFA base_url 探测）——这类请求会把真实 API Key / FOFA Key 放进 Authorization/query，
一旦 base_url 被篡改指向内网或云元数据，就会造成密钥外泄 + 内网探测。

注意：Worker/killsweep/report_assistant 主动挖洞的 http_request/run_shell 属于产品语义
（就是要打目标，可能含内网），不走本模块。

防 DNS rebinding：`pinned_outbound_request` 返回把 host 替换为已校验 IP 的请求参数
（Host 头与 TLS SNI/证书校验保持原域名），调用方用它发起请求即保证
「连接的 IP == 校验通过的 IP」，不存在校验后二次解析的 TOCTOU 窗口。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

_ALLOWED_SCHEMES = {"http", "https"}
# 云厂商元数据地址（link-local + 部分厂商特例）。
_METADATA_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",       # 阿里云
    "metadata.google.internal",
    "metadata.tencentyun.com",
}


class SsrfBlocked(ValueError):
    """出站地址命中 SSRF 黑名单。"""


def _ip_is_forbidden(ip: ipaddress._BaseAddress, *, allow_private: bool = False) -> bool:
    # IPv4-mapped IPv6（如 ::ffff:127.0.0.1）显式展开后判定，避免依赖
    # is_loopback/is_private 对映射段的版本相关行为（Python <=3.12.3 有差异）。
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # 私有网段豁免（如自建内网 FOFA/LLM 镜像）时，仅禁元数据与保留段；
    # is_private 已排除 loopback/link_local，其余内网段在此豁免。
    if not allow_private and ip.is_private:
        return True
    return False


def _validate_and_resolve(
    url: str, *, allow_extra_hosts: set[str] | None = None, allow_private: bool = False
) -> tuple[urlparse.ParseResult, str, list[str]]:
    """校验 URL 并返回 (parsed, host, 校验通过的 IP 列表)。不安全时抛 SsrfBlocked。"""
    raw = str(url or "").strip()
    if not raw:
        raise SsrfBlocked("空 URL")
    try:
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").strip().lower()
    except ValueError as exc:
        # 畸形方括号 IPv6（如 http://[250:4809:...:b092]）会让 urlparse 在解析期抛
        # ValueError；调用方(settings_service.fetch_models)只捕获 SsrfBlocked，裸
        # ValueError 会一路冒泡打崩配置探测。这里 fail-closed 转成 SsrfBlocked。
        raise SsrfBlocked(f"URL 无法解析（疑似畸形 IPv6）: {raw[:80]}") from exc
    if scheme not in _ALLOWED_SCHEMES:
        raise SsrfBlocked(f"不允许的协议: {scheme or '(空)'}")
    if not host:
        raise SsrfBlocked("URL 缺少主机名")

    extra = {h.strip().lower() for h in (allow_extra_hosts or set()) if h}
    if host not in extra:
        if host in _METADATA_HOSTS:
            raise SsrfBlocked("目标为云元数据地址，已拦截")

        # 逐个解析出的 IP 校验（含 IPv6、DNS 到内网的情形）。
        from app.urlnorm import safe_port
        port = safe_port(parsed) or (443 if scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise SsrfBlocked(f"主机解析失败: {host}") from exc

        ips: list[str] = []
        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                raise SsrfBlocked(f"无效 IP: {ip_str}")
            if _ip_is_forbidden(ip, allow_private=allow_private):
                raise SsrfBlocked(f"目标解析到私有/保留地址({ip_str})，已拦截")
            if ip_str not in ips:
                ips.append(ip_str)
        if not ips:
            raise SsrfBlocked(f"主机无可用解析结果: {host}")

    else:
        ips = []
    return parsed, host, ips


def assert_safe_outbound_url(
    url: str,
    *,
    allow_extra_hosts: set[str] | None = None,
    allow_private: bool = False,
) -> str:
    """校验并返回原 URL；不安全时抛 SsrfBlocked。

    allow_extra_hosts：显式放行的 host（如用户在 env 里配置的私有 FOFA 代理域名）。
    allow_private：豁免私有网段（自建内网镜像场景）；元数据/回环/链路本地仍一律拦截。
    注意：本函数只校验不绑定，校验与真实连接之间仍有一次 DNS 解析窗口；
    携带密钥的探测请求请改用 `pinned_outbound_request`。
    """
    _validate_and_resolve(url, allow_extra_hosts=allow_extra_hosts, allow_private=allow_private)
    return str(url or "").strip()


def pinned_outbound_request(
    url: str, *, allow_extra_hosts: set[str] | None = None
) -> dict:
    """校验并把请求绑定到已校验的解析 IP，堵 DNS rebinding TOCTOU。

    返回 httpx 请求参数：
    - url：host 已替换为校验通过的 IP（其余成分不变）
    - headers：附加 Host 头（保持原域名，网关/虚拟主机路由不受影响）
    - extensions：https 时 {"sni_hostname": 原域名}，TLS SNI 与证书校验仍按原域名进行
      （httpx>=0.24 + httpcore 透传支持；项目 requirements 锁定 httpx>=0.27）

    调用方：client.request(method, **pinned, ...)。
    """
    parsed, host, ips = _validate_and_resolve(url, allow_extra_hosts=allow_extra_hosts)
    if not ips:
        # extra_hosts 豁免的显式域名：用户明确配置的私有代理，不做 IP 绑定，仅校验过
        return {"url": str(url or "").strip(), "headers": {}, "extensions": {}}

    pin_ip = ips[0]  # 与 anyio 默认 getaddrinfo 顺序一致，优先首个记录
    scheme = (parsed.scheme or "http").lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    netloc = f"[{pin_ip}]" if ":" in pin_ip else pin_ip
    if port != default_port:
        netloc = f"{netloc}:{port}"
    if parsed.username:
        cred = parsed.username
        if parsed.password:
            cred = f"{cred}:{parsed.password}"
        netloc = f"{cred}@{netloc}"
    pin_url = urlunparse((scheme, netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

    # Host 头保留原 authority（含非常规端口；IPv6 原样带方括号）
    headers = {"Host": parsed.netloc.rsplit("@", 1)[-1]}
    extensions = {"sni_hostname": host} if scheme == "https" else {}
    return {"url": pin_url, "headers": headers, "extensions": extensions}
