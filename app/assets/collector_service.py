"""双图全局资产引擎 + 多源自动化资产收集服务。

核心设计：
1. 全局六类资产真值库（GlobalAsset）：root_domain / subdomain / ip / service / app / endpoint，
   统一幂等 Upsert（数组列去重并集、标量补空/更新探活态、显式企业归属 explicit 不被 scope 覆盖）。
2. 双图拓扑构建（build_dual_graph）：支持全局视图与单任务视图，将资产图与探索图（goal/fact/finding/hint）
   通过 anchors / proves / yields / covers 边串联，并支持任意节点双向血缘回溯与覆盖率计算。
3. 自动化资产收集流水线（run_collect_job）：支持被动证书透明度（crt.sh）、6 大测绘引擎、
   并发 DNS 解析、轻量只读 HTTP 存活/指纹/接口发现与平台任务资产同步。
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import socket
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    AssetCollectJob,
    AssetCompany,
    Finding,
    FusionGoal,
    FusionTraffic,
    GlobalAsset,
    Target,
    Task,
    TaskEvent,
    to_cst_iso,
)
from app.db.session import SessionLocal
from app.engines import get_engine
from app.fusion import graphs as fusion_graphs
from app.fusion import scope_guard
from app.settings_service import resolve_engine_base_url, resolve_engine_key

logger = logging.getLogger("riddle.assets")

ASSET_TYPES = ("root_domain", "subdomain", "ip", "service", "app", "endpoint")

_TITLE_RE = re.compile(r"<title[^>]*>([\s\S]{1,300}?)</title>", re.IGNORECASE)
_ENDPOINT_LINK_RE = re.compile(
    r"""(?:href|action|src)\s*=\s*["']([^"'#\s]{2,220})["']""",
    re.IGNORECASE,
)
_STATIC_EXTS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp",
)

_TECH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("Nginx", re.compile(r"\bnginx\b", re.I)),
    ("Apache", re.compile(r"\bapache\b", re.I)),
    ("IIS", re.compile(r"\bmicrosoft-iis\b", re.I)),
    ("Tomcat", re.compile(r"\bapache-coyote\b|\btomcat\b", re.I)),
    ("Spring/Java", re.compile(r"jsessionid|whitelabel error page|spring", re.I)),
    ("Shiro", re.compile(r"rememberme=deleteme", re.I)),
    ("PHP", re.compile(r"\bphp\b|phpsessid", re.I)),
    ("ASP.NET", re.compile(r"asp\.net|aspsessionid|__viewstate", re.I)),
    ("Vue.js", re.compile(r"__vue__|vue\.runtime|app\.[0-9a-f]+\.js", re.I)),
    ("React", re.compile(r"__react|react-dom|data-reactroot", re.I)),
    ("JeecgBoot", re.compile(r"jeecg-boot|jeecgboot", re.I)),
    ("WordPress", re.compile(r"wp-content|wp-includes", re.I)),
    ("Cloudflare", re.compile(r"cloudflare|cf-ray", re.I)),
    ("OpenResty", re.compile(r"openresty", re.I)),
    ("Swagger/OpenAPI", re.compile(r"swagger-ui|openapi", re.I)),
]

# ── 运行态任务取消管理 ────────────────────────────────────────
_COLLECT_LOCK = threading.Lock()
_COLLECT_CANCEL: dict[str, threading.Event] = {}
_COLLECT_TASKS: dict[str, asyncio.Task] = {}


def is_collect_job_running(job_id: str) -> bool:
    with _COLLECT_LOCK:
        t = _COLLECT_TASKS.get(job_id)
        return t is not None and not t.done()


def cancel_collect_job(job_id: str) -> bool:
    with _COLLECT_LOCK:
        ev = _COLLECT_CANCEL.get(job_id)
        if ev is not None:
            ev.set()
            return True
    return False


# ── 归一化与归属匹配 ──────────────────────────────────────────
def normalize_company_key(name: str) -> str:
    return re.sub(r"\s+", "", (name or "").strip().lower())


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def calc_c_segment(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address((ip_str or "").strip())
        if addr.version == 4:
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
            return str(net)
        net = ipaddress.ip_network(f"{addr}/48", strict=False)
        return str(net)
    except ValueError:
        return ""


def _union_list(old: list | None, new: list | None, limit: int = 200) -> list:
    out: list = []
    seen: set[str] = set()
    for item in [*(old or []), *(new or [])]:
        if item is None or item == "":
            continue
        key = str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
        if len(out) >= limit:
            break
    return out


def normalize_scope_rules(rules: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    valid_kinds = {"domain", "ip", "cidr", "icp", "keyword"}
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        kind = str(r.get("kind") or "").strip().lower()
        val = str(r.get("value") or "").strip()
        if kind not in valid_kinds or not val:
            continue
        if kind == "domain":
            val = val.lower().lstrip("*.")
        key = (kind, val.lower())
        if key not in seen:
            seen.add(key)
            out.append({"kind": kind, "value": val})
    return out


def match_company_for_asset(
    companies: list[AssetCompany],
    *,
    domain: str = "",
    ip: str = "",
) -> AssetCompany | None:
    dom = (domain or "").strip().lower().rstrip(".")
    ip_clean = (ip or "").strip()
    ip_obj = None
    if ip_clean:
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
        except ValueError:
            ip_obj = None

    for comp in companies:
        for rule in comp.scope_rules or []:
            kind = str(rule.get("kind") or "").lower()
            val = str(rule.get("value") or "").strip()
            if not val:
                continue
            if kind == "domain" and dom:
                target_dom = val.lower().lstrip("*.")
                if dom == target_dom or dom.endswith("." + target_dom):
                    return comp
            elif kind == "ip" and ip_clean and ip_clean == val:
                return comp
            elif kind == "cidr" and ip_obj is not None:
                try:
                    if ip_obj in ipaddress.ip_network(val, strict=False):
                        return comp
                except ValueError:
                    continue
    return None


def parse_seed_inputs(raw_seeds: list[str] | str) -> dict[str, list[str]]:
    """解析用户输入的混合种子（根域名 / URL / IP / CIDR），自动去重并限制单个 CIDR 展开上限。"""
    tokens: list[str] = []
    if isinstance(raw_seeds, str):
        tokens = [t.strip() for t in re.split(r"[\r\n,;]+", raw_seeds) if t.strip()]
    else:
        for item in raw_seeds:
            tokens.extend([t.strip() for t in re.split(r"[\r\n,;]+", str(item or "")) if t.strip()])

    domains: list[str] = []
    urls: list[str] = []
    ips: list[str] = []
    cidrs: list[str] = []
    seen: set[str] = set()

    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        if tok.startswith(("http://", "https://")):
            urls.append(tok)
            host = scope_guard.normalize_host(tok)
            if host and not is_valid_ip(host) and host not in domains:
                domains.append(host)
            elif host and is_valid_ip(host) and host not in ips:
                ips.append(host)
            continue

        if "/" in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                cidrs.append(str(net))
                # 单个 CIDR 最多安全展开 256 个宿主地址，防止大网段误扫
                for idx, host_ip in enumerate(net.hosts() if net.num_addresses > 2 else [net.network_address]):
                    if idx >= 256:
                        break
                    s = str(host_ip)
                    if s not in ips:
                        ips.append(s)
                continue
            except ValueError:
                pass

        if is_valid_ip(tok):
            ips.append(tok)
            continue

        host = scope_guard.normalize_host(tok)
        if host and "." in host:
            if is_valid_ip(host):
                if host not in ips:
                    ips.append(host)
            elif host not in domains:
                domains.append(host)

    return {"domains": domains, "urls": urls, "ips": ips, "cidrs": cidrs}


# ── 核心幂等 Upsert 引擎 ──────────────────────────────────────
async def upsert_global_asset(
    session: AsyncSession,
    *,
    asset_type: str,
    dedup_key: str,
    value: str,
    company_id: str | None = None,
    company_name: str = "",
    company_source: str = "scope",
    root_domain: str = "",
    host: str = "",
    ip: str = "",
    port: int = 0,
    protocol: str = "",
    status_code: int = 0,
    title: str = "",
    technologies: list[str] | None = None,
    open_ports: list[int] | None = None,
    bound_domains: list[str] | None = None,
    method: str = "",
    params: list[str] | None = None,
    source: str = "auto_collect",
    task_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    companies_cache: list[AssetCompany] | None = None,
) -> tuple[GlobalAsset, bool]:
    """按 (asset_type, dedup_key) 幂等写入/合并全球资产图节点。返回 (row, is_new)。"""
    atype = asset_type.strip().lower()
    if atype not in ASSET_TYPES:
        raise ValueError(f"不支持的资产类型: {asset_type}")
    dkey = dedup_key.strip()[:512]
    if not dkey:
        raise ValueError("dedup_key 不能为空")

    clean_ip = ip.strip() if is_valid_ip(ip) else ""
    clean_host = scope_guard.normalize_host(host) if host else ""
    clean_root = root_domain.strip().lower() or (scope_guard.root_domain(clean_host) if clean_host and not is_valid_ip(clean_host) else "")
    c_seg = calc_c_segment(clean_ip) if clean_ip else ""

    # 自动按公司范围规则归属（若未显式指定）
    resolved_cid = company_id
    resolved_cname = company_name
    resolved_csource = company_source if company_id else "scope"
    if not resolved_cid and companies_cache:
        matched = match_company_for_asset(companies_cache, domain=clean_host or clean_root, ip=clean_ip)
        if matched is not None:
            resolved_cid = matched.id
            resolved_cname = matched.name
            resolved_csource = "scope"

    existing = (
        await session.execute(
            select(GlobalAsset).where(GlobalAsset.asset_type == atype, GlobalAsset.dedup_key == dkey)
        )
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing is None:
        row = GlobalAsset(
            asset_type=atype,
            dedup_key=dkey,
            value=(value or dkey)[:1000],
            company_id=resolved_cid,
            company_name=resolved_cname[:200],
            company_source=resolved_csource,
            root_domain=clean_root[:255],
            host=clean_host[:255],
            ip=clean_ip[:64],
            c_segment=c_seg[:64],
            port=int(port or 0),
            protocol=(protocol or "").strip().lower()[:32],
            status_code=int(status_code or 0),
            title=(title or "").strip()[:500],
            technologies=_union_list([], technologies),
            open_ports=_union_list([], open_ports),
            bound_domains=_union_list([], bound_domains),
            method=(method or "").strip().upper()[:16],
            params=_union_list([], params),
            source=source[:32],
            task_ids=_union_list([], task_ids),
            metadata_json=dict(metadata or {}),
            first_seen=now,
            last_seen=now,
        )
        session.add(row)
        await session.flush()
        return row, True

    # 合并更新：不变量 —— explicit 归属绝不被 scope 覆盖
    if resolved_cid:
        if resolved_csource == "explicit" or existing.company_source != "explicit":
            existing.company_id = resolved_cid
            existing.company_name = resolved_cname[:200]
            existing.company_source = resolved_csource

    if not existing.root_domain and clean_root:
        existing.root_domain = clean_root[:255]
    if not existing.host and clean_host:
        existing.host = clean_host[:255]
    if not existing.ip and clean_ip:
        existing.ip = clean_ip[:64]
    if not existing.c_segment and c_seg:
        existing.c_segment = c_seg[:64]
    if not existing.port and port:
        existing.port = int(port)
    if not existing.protocol and protocol:
        existing.protocol = protocol.strip().lower()[:32]
    if status_code:
        existing.status_code = int(status_code)
    if title and (not existing.title or source == "http_probe"):
        existing.title = title.strip()[:500]
    if method and not existing.method:
        existing.method = method.strip().upper()[:16]

    existing.technologies = _union_list(existing.technologies, technologies)
    existing.open_ports = _union_list(existing.open_ports, open_ports)
    existing.bound_domains = _union_list(existing.bound_domains, bound_domains)
    existing.params = _union_list(existing.params, params)
    existing.task_ids = _union_list(existing.task_ids, task_ids)
    if metadata:
        existing.metadata_json = {**(existing.metadata_json or {}), **metadata}
    existing.last_seen = now
    return existing, False


async def claim_assets_for_company(session: AsyncSession, company: AssetCompany) -> int:
    """按公司 scope_rules 自动认领存量未显式绑定资产，遵守 explicit 不变式。"""
    if not company.scope_rules:
        return 0
    rows = (
        await session.execute(select(GlobalAsset).where(GlobalAsset.company_source != "explicit"))
    ).scalars().all()
    claimed = 0
    for row in rows:
        matched = match_company_for_asset([company], domain=row.host or row.root_domain or row.value, ip=row.ip)
        if matched is not None and row.company_id != company.id:
            row.company_id = company.id
            row.company_name = company.name
            row.company_source = "scope"
            claimed += 1
    return claimed


async def ingest_url_into_assets(
    session: AsyncSession,
    *,
    url: str = "",
    host: str = "",
    ip: str = "",
    port: int = 0,
    title: str = "",
    status_code: int = 0,
    technologies: list[str] | None = None,
    method: str = "GET",
    source: str = "auto_collect",
    task_id: str = "",
    company_id: str | None = None,
    company_name: str = "",
    company_source: str = "scope",
    companies_cache: list[AssetCompany] | None = None,
) -> dict[str, int]:
    """把一条 URL/Host/IP 拆解落盘为关联的 root_domain / subdomain / ip / service / app / endpoint。"""
    counts = {k: 0 for k in ASSET_TYPES}
    task_ids = [task_id] if task_id else []

    raw_url = (url or "").strip()
    parsed = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}") if raw_url else None
    clean_host = scope_guard.normalize_host(host or (parsed.hostname if parsed else "") or raw_url)
    clean_ip = ip.strip() if is_valid_ip(ip) else (clean_host if is_valid_ip(clean_host) else "")
    scheme = (parsed.scheme.lower() if parsed and parsed.scheme else ("https" if port == 443 else "http"))
    eff_port = int(port or (parsed.port if parsed and parsed.port else (443 if scheme == "https" else 80)))
    root_dom = scope_guard.root_domain(clean_host) if clean_host and not is_valid_ip(clean_host) else ""

    common = dict(
        company_id=company_id,
        company_name=company_name,
        company_source=company_source,
        source=source,
        task_ids=task_ids,
        companies_cache=companies_cache,
    )

    if root_dom:
        _, is_new = await upsert_global_asset(
            session,
            asset_type="root_domain",
            dedup_key=root_dom,
            value=root_dom,
            root_domain=root_dom,
            host=root_dom,
            **common,
        )
        if is_new:
            counts["root_domain"] += 1

    if clean_host and not is_valid_ip(clean_host):
        _, is_new = await upsert_global_asset(
            session,
            asset_type="subdomain",
            dedup_key=clean_host,
            value=clean_host,
            root_domain=root_dom,
            host=clean_host,
            ip=clean_ip,
            **common,
        )
        if is_new:
            counts["subdomain"] += 1

    if clean_ip:
        _, is_new = await upsert_global_asset(
            session,
            asset_type="ip",
            dedup_key=clean_ip,
            value=clean_ip,
            root_domain=root_dom,
            host=clean_host or clean_ip,
            ip=clean_ip,
            open_ports=[eff_port] if eff_port else [],
            bound_domains=[clean_host] if clean_host and not is_valid_ip(clean_host) else [],
            **common,
        )
        if is_new:
            counts["ip"] += 1

    service_host = clean_host or clean_ip
    if service_host and (raw_url or eff_port):
        default_port = (scheme == "http" and eff_port == 80) or (scheme == "https" and eff_port == 443)
        service_url = f"{scheme}://{service_host}" if default_port else f"{scheme}://{service_host}:{eff_port}"
        _, is_new = await upsert_global_asset(
            session,
            asset_type="service",
            dedup_key=service_url.lower(),
            value=service_url,
            root_domain=root_dom,
            host=service_host,
            ip=clean_ip,
            port=eff_port,
            protocol=scheme,
            status_code=status_code,
            title=title,
            technologies=technologies,
            **common,
        )
        if is_new:
            counts["service"] += 1

        if title and len(title.strip()) >= 2:
            app_key = f"{service_host}:{title.strip().lower()[:120]}"
            _, is_new = await upsert_global_asset(
                session,
                asset_type="app",
                dedup_key=app_key,
                value=title.strip()[:200],
                root_domain=root_dom,
                host=service_host,
                ip=clean_ip,
                port=eff_port,
                protocol=scheme,
                title=title.strip()[:200],
                technologies=technologies,
                **common,
            )
            if is_new:
                counts["app"] += 1

        if parsed and parsed.path and parsed.path != "/":
            ep_url = f"{service_url}{parsed.path}"
            ep_method = (method or "GET").upper()
            qparams = list(parse_qs(parsed.query).keys()) if parsed.query else []
            _, is_new = await upsert_global_asset(
                session,
                asset_type="endpoint",
                dedup_key=f"{ep_method}:{ep_url.lower()}",
                value=ep_url,
                root_domain=root_dom,
                host=service_host,
                ip=clean_ip,
                port=eff_port,
                protocol=scheme,
                status_code=status_code,
                method=ep_method,
                params=qparams,
                **common,
            )
            if is_new:
                counts["endpoint"] += 1

    return counts


async def sync_task_data_to_global_assets(
    session: AsyncSession,
    *,
    task_id: str | None = None,
    seed_domains: set[str] | None = None,
) -> dict[str, int]:
    """把既有 Task 的 Target / Finding / FusionTraffic 增量同步到全局六类资产库。"""
    companies = (await session.execute(select(AssetCompany))).scalars().all()
    totals = {k: 0 for k in ASSET_TYPES}
    processed = 0

    t_stmt = select(Target)
    if task_id:
        t_stmt = t_stmt.where(Target.task_id == task_id)
    targets = (await session.execute(t_stmt.order_by(desc(Target.id)).limit(2000))).scalars().all()

    for tg in targets:
        host = scope_guard.normalize_host(tg.host or tg.url)
        if seed_domains and host:
            if not any(host == d or host.endswith("." + d) for d in seed_domains):
                continue
        c = await ingest_url_into_assets(
            session,
            url=tg.url,
            host=tg.host,
            ip=tg.ip,
            title=tg.title,
            source="task_sync",
            task_id=tg.task_id,
            companies_cache=companies,
        )
        for k, v in c.items():
            totals[k] += v
        processed += 1

    tr_stmt = select(FusionTraffic)
    if task_id:
        tr_stmt = tr_stmt.where(FusionTraffic.task_id == task_id)
    traffics = (await session.execute(tr_stmt.order_by(desc(FusionTraffic.created_at)).limit(1000))).scalars().all()
    for tr in traffics:
        host = scope_guard.normalize_host(tr.url)
        if seed_domains and host:
            if not any(host == d or host.endswith("." + d) for d in seed_domains):
                continue
        c = await ingest_url_into_assets(
            session,
            url=tr.url,
            method=tr.method or "GET",
            status_code=int(tr.status_code or 0),
            source="task_sync",
            task_id=tr.task_id,
            companies_cache=companies,
        )
        for k, v in c.items():
            totals[k] += v
        processed += 1

    totals["processed"] = processed
    return totals


# ── DSL 资产检索过滤 ──────────────────────────────────────────
def filter_assets_by_dsl(rows: list[GlobalAsset], query: str) -> list[GlobalAsset]:
    """支持简洁 DSL 语法过滤资产：port:443 status:200 tech:nginx domain:edu.cn ip:10.0 method:POST company:xx。"""
    q = (query or "").strip()
    if not q:
        return rows

    tokens = re.findall(r'(?:[^\s"]+|"[^"]*")+', q)
    predicates: list[tuple[str, str]] = []
    free_terms: list[str] = []
    for tok in tokens:
        if ":" in tok and not tok.startswith(("http:", "https:")):
            k, v = tok.split(":", 1)
            k = k.strip().lower()
            v = v.strip().strip('"').lower()
            if k in {"port", "status", "tech", "domain", "host", "ip", "method", "company", "source", "type"} and v:
                predicates.append((k, v))
                continue
        free_terms.append(tok.strip('"').lower())

    out: list[GlobalAsset] = []
    for row in rows:
        matched = True
        for k, v in predicates:
            if k == "port" and str(row.port or "") != v and v not in [str(p) for p in (row.open_ports or [])]:
                matched = False
            elif k == "status" and str(row.status_code or "") != v:
                matched = False
            elif k == "tech" and not any(v in str(t).lower() for t in (row.technologies or [])):
                matched = False
            elif k == "domain" and v not in (row.root_domain or "").lower() and v not in (row.host or "").lower():
                matched = False
            elif k == "host" and v not in (row.host or "").lower() and v not in (row.value or "").lower():
                matched = False
            elif k == "ip" and v not in (row.ip or "").lower() and v not in (row.c_segment or "").lower():
                matched = False
            elif k == "method" and (row.method or "").lower() != v:
                matched = False
            elif k == "company" and v not in (row.company_name or "").lower():
                matched = False
            elif k == "source" and v not in (row.source or "").lower():
                matched = False
            elif k == "type" and (row.asset_type or "").lower() != v:
                matched = False
            if not matched:
                break
        if not matched:
            continue
        if free_terms:
            hay = " ".join([
                row.value or "",
                row.host or "",
                row.root_domain or "",
                row.ip or "",
                row.title or "",
                row.company_name or "",
                " ".join(str(t) for t in (row.technologies or [])),
            ]).lower()
            if not all(term in hay for term in free_terms):
                continue
        out.append(row)
    return out


# ── 双图拓扑构建（全局资产图 × 任务探索图 + 锚点血缘）─────────
def _gid(*parts: Any) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:20]


async def build_dual_graph(
    session: AsyncSession,
    *,
    task_id: str | None = None,
    company_id: str | None = None,
    limit: int = 240,
) -> dict[str, Any]:
    """构建可视化双图数据（资产图 + 探索图 + anchors/proves/yields/covers 跨图边 + 覆盖统计）。"""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_seen: set[tuple[str, str, str]] = set()

    def add_node(nid: str, graph: str, kind: str, label: str, ref_id: str = "", payload: dict | None = None):
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "graph": graph,
                "kind": kind,
                "label": str(label or "")[:120],
                "ref_id": str(ref_id or ""),
                "payload": payload or {},
            }

    def add_edge(kind: str, src: str, dst: str):
        if not src or not dst or src == dst:
            return
        if src not in nodes or dst not in nodes:
            return
        key = (kind, src, dst)
        if key not in edge_seen:
            edge_seen.add(key)
            edges.append({"id": _gid("e", kind, src, dst), "kind": kind, "src": src, "dst": dst})

    # 1) 资产图节点来源：优先读取 GlobalAsset，单任务模式同时合并 Target
    asset_stmt = select(GlobalAsset).order_by(desc(GlobalAsset.last_seen)).limit(limit)
    if company_id:
        asset_stmt = asset_stmt.where(GlobalAsset.company_id == company_id)
    global_assets = (await session.execute(asset_stmt)).scalars().all()
    if task_id:
        global_assets = [a for a in global_assets if task_id in (a.task_ids or [])]

    # 建索引方便连边
    root_nid_by_dom: dict[str, str] = {}
    sub_nid_by_host: dict[str, str] = {}
    ip_nid_by_ip: dict[str, str] = {}
    svc_nid_by_host: dict[str, str] = {}
    comp_nid_by_id: dict[str, str] = {}

    for a in global_assets:
        nid = _gid("asset", a.asset_type, a.dedup_key)
        add_node(
            nid,
            "asset",
            a.asset_type,
            a.title if a.asset_type == "app" and a.title else a.value,
            a.id,
            {
                "value": a.value,
                "host": a.host,
                "ip": a.ip,
                "port": a.port,
                "status_code": a.status_code,
                "title": a.title,
                "technologies": a.technologies or [],
                "company_name": a.company_name,
                "source": a.source,
            },
        )
        if a.company_id and a.company_name:
            cnid = _gid("asset", "company", a.company_id)
            add_node(cnid, "asset", "company", a.company_name, a.company_id, {"name": a.company_name})
            comp_nid_by_id[a.company_id] = cnid
            if a.asset_type == "root_domain":
                add_edge("belongs_to", nid, cnid)

        if a.asset_type == "root_domain":
            root_nid_by_dom[a.dedup_key] = nid
        elif a.asset_type == "subdomain":
            sub_nid_by_host[a.host or a.dedup_key] = nid
        elif a.asset_type == "ip":
            ip_nid_by_ip[a.ip or a.dedup_key] = nid
        elif a.asset_type == "service":
            svc_nid_by_host.setdefault(a.host or a.ip, nid)

    # 若单任务模式下 GlobalAsset 尚未同步，直接用 Target 兜底构建资产图
    if task_id and not global_assets:
        t_rows = (await session.execute(select(Target).where(Target.task_id == task_id).limit(120))).scalars().all()
        t_dicts = [{"id": t.id, "url": t.url, "host": t.host, "ip": t.ip, "title": t.title} for t in t_rows]
        anodes, aedges = fusion_graphs.asset_nodes(t_dicts)
        for n in anodes:
            add_node(n["id"], "asset", n["kind"], n["label"], n.get("ref_id", ""), n.get("payload"))
            if n["kind"] == "subdomain":
                sub_nid_by_host[n["label"]] = n["id"]
            elif n["kind"] == "root_domain":
                root_nid_by_dom[n["label"]] = n["id"]
        for e in aedges:
            add_edge(e["kind"], e["src"], e["dst"])
    else:
        # 资产图内部关系连边：endpoint -> service/subdomain -> root_domain, subdomain -> ip, app -> service/subdomain
        for a in global_assets:
            nid = _gid("asset", a.asset_type, a.dedup_key)
            if a.asset_type == "subdomain":
                if a.root_domain and a.root_domain in root_nid_by_dom:
                    add_edge("anchors", nid, root_nid_by_dom[a.root_domain])
                if a.ip and a.ip in ip_nid_by_ip:
                    add_edge("resolves_to", nid, ip_nid_by_ip[a.ip])
            elif a.asset_type == "service":
                if a.host and a.host in sub_nid_by_host:
                    add_edge("hosts", nid, sub_nid_by_host[a.host])
                elif a.ip and a.ip in ip_nid_by_ip:
                    add_edge("hosts", nid, ip_nid_by_ip[a.ip])
            elif a.asset_type in ("app", "endpoint"):
                parent = svc_nid_by_host.get(a.host) or sub_nid_by_host.get(a.host) or ip_nid_by_ip.get(a.ip)
                if parent:
                    add_edge("anchors", nid, parent)

    # 2) 探索图节点（Goal / Finding / Fact / Hint）与跨图锚点边（anchors / proves / yields）
    f_stmt = select(Finding).where(Finding.status != "superseded").order_by(desc(Finding.created_at)).limit(80)
    if task_id:
        f_stmt = f_stmt.where(Finding.task_id == task_id)
    findings = (await session.execute(f_stmt)).scalars().all()

    g_stmt = select(FusionGoal).order_by(desc(FusionGoal.created_at)).limit(40)
    if task_id:
        g_stmt = g_stmt.where(FusionGoal.task_id == task_id)
    goals = (await session.execute(g_stmt)).scalars().all()

    goal_nids: dict[str, tuple[str, str, list[str]]] = {}
    for g in goals:
        gnid = _gid("explore", "goal", g.id)
        add_node(
            gnid,
            "exploration",
            "goal",
            g.title,
            g.goal_key or g.id,
            {"criteria": g.criteria, "status": g.status, "kind": g.kind},
        )
        goal_nids[g.id] = (gnid, g.title or "", [str(x) for x in (g.match_terms or []) if x])

    anchored_asset_ids: set[str] = set()
    for f in findings:
        fnid = _gid("explore", "finding", f.id)
        add_node(
            fnid,
            "exploration",
            "finding",
            f.title,
            f.id,
            {"vuln_type": f.vuln_type, "severity": f.severity_claimed, "target_url": f.target_url},
        )
        # 锚定到资产图对应主机/服务/根域节点
        fhost = scope_guard.normalize_host(f.target_url)
        anchor_target = (
            svc_nid_by_host.get(fhost)
            or sub_nid_by_host.get(fhost)
            or root_nid_by_dom.get(scope_guard.root_domain(fhost) if fhost else "")
        )
        if anchor_target:
            add_edge("anchors", fnid, anchor_target)
            anchored_asset_ids.add(anchor_target)

        # 证明目标：支持 match_terms、漏洞类型命中及中英文短语双向包含
        ftitle = (f.title or "").strip()
        fvtype = (f.vuln_type or "").strip()
        fblob = f"{ftitle} {fvtype}".lower()
        for _, (gnid, gtitle, mterms) in goal_nids.items():
            gt_low = gtitle.lower()
            tokens = [w.lower() for w in re.split(r"[\s，,、/|；;]+", gtitle) if len(w) >= 2]
            matched_goal = (
                (mterms and any(t.lower() in fblob for t in mterms))
                or (fvtype and len(fvtype) >= 2 and fvtype.lower() in gt_low)
                or (ftitle and len(ftitle) >= 4 and (ftitle.lower() in gt_low or gt_low in ftitle.lower()))
                or (tokens and any(t in fblob for t in tokens))
            )
            if matched_goal:
                add_edge("proves", fnid, gnid)

        # 复现步骤事实节点（最多 3 条防图过密）
        for idx, step in enumerate((f.steps or [])[:3]):
            desc_text = step.get("desc", "") if isinstance(step, dict) else str(step or "")
            if desc_text.strip():
                fact_nid = _gid("explore", "fact", f.id, idx)
                add_node(fact_nid, "exploration", "fact", desc_text.strip()[:90], f.id, {})
                add_edge("yields", fact_nid, fnid)

    if task_id:
        ev_rows = (
            await session.execute(
                select(TaskEvent).where(TaskEvent.task_id == task_id).order_by(desc(TaskEvent.id)).limit(12)
            )
        ).scalars().all()
        for ev in ev_rows:
            if ev.kind in ("killsweep_task_created", "finding_accepted", "target_done"):
                hnid = _gid("explore", "hint", ev.id)
                add_node(hnid, "exploration", "hint", ev.message[:90] or ev.kind, str(ev.id), {"kind": ev.kind})

    node_list = list(nodes.values())
    asset_count = sum(1 for n in node_list if n["graph"] == "asset")
    explore_count = sum(1 for n in node_list if n["graph"] == "exploration")
    by_kind: dict[str, int] = {}
    for n in node_list:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1

    coverage = {
        "asset_nodes": asset_count,
        "exploration_nodes": explore_count,
        "edges": len(edges),
        "anchored_assets": len(anchored_asset_ids),
        "ratio": round(len(anchored_asset_ids) / asset_count, 3) if asset_count else 0.0,
        "by_kind": by_kind,
    }
    return {
        "task_id": task_id or "",
        "nodes": node_list,
        "edges": edges,
        "coverage": coverage,
    }


# ── 多源自动化资产收集流水线 ──────────────────────────────────
async def _probe_http_host(
    client: httpx.AsyncClient,
    url_candidate: str,
) -> dict[str, Any] | None:
    """只读轻量 HTTP 探测：提取状态码、标题、Server/技术栈指纹与同站发现端点。"""
    try:
        resp = await client.get(url_candidate, follow_redirects=True)
    except Exception:
        return None

    final_url = str(resp.url)
    body = ""
    ct = (resp.headers.get("content-type") or "").lower()
    if any(k in ct for k in ("text/", "json", "xml", "javascript", "html")) or not ct:
        body = (resp.text or "")[:32000]

    title = ""
    m = _TITLE_RE.search(body)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    fingerprint_blob = f"{header_blob}\n{body[:8000]}"
    techs: list[str] = []
    for tech_name, pat in _TECH_SIGNATURES:
        if pat.search(fingerprint_blob):
            techs.append(tech_name)
    server_hdr = (resp.headers.get("server") or "").strip()
    if server_hdr and len(server_hdr) <= 60:
        techs.append(server_hdr)

    # 提取同主机轻量页面端点（排除静态资源）
    endpoints: list[str] = []
    base_host = scope_guard.normalize_host(final_url)
    seen_ep: set[str] = set()
    for link in _ENDPOINT_LINK_RE.findall(body):
        if link.startswith(("javascript:", "mailto:", "data:", "tel:")):
            continue
        abs_url = urljoin(final_url, link)
        sp = urlsplit(abs_url)
        if sp.scheme not in ("http", "https"):
            continue
        if scope_guard.normalize_host(abs_url) != base_host:
            continue
        path_low = (sp.path or "/").lower()
        if path_low == "/" or path_low.endswith(_STATIC_EXTS):
            continue
        clean_ep = f"{sp.scheme}://{sp.netloc}{sp.path}"
        if clean_ep not in seen_ep:
            seen_ep.add(clean_ep)
            endpoints.append(clean_ep)
        if len(endpoints) >= 15:
            break

    return {
        "url": final_url,
        "status_code": resp.status_code,
        "title": title,
        "technologies": _union_list([], techs, limit=20),
        "endpoints": endpoints,
    }


async def _fetch_crtsh_subdomains(root_domain: str, timeout: float = 12.0) -> list[str]:
    """被动查询 crt.sh 证书透明度日志获取历史与在用子域名。"""
    url = f"https://crt.sh/?q=%.{root_domain}&output=json"
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=True, headers={"User-Agent": "Riddle-AssetCollector/1.0"}) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
            if not isinstance(data, list):
                return []
            for row in data[:500]:
                nv = str(row.get("name_value") or "")
                for line in nv.splitlines():
                    h = line.strip().lower().lstrip("*.")
                    if h and (h == root_domain or h.endswith("." + root_domain)) and " " not in h:
                        found.add(h)
    except Exception as exc:
        logger.debug("crt.sh lookup skipped for %s: %s", root_domain, exc)
    return sorted(found)[:200]


async def _resolve_dns_batch(hosts: list[str], concurrency: int = 20) -> dict[str, list[str]]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    results: dict[str, list[str]] = {}

    async def _one(h: str):
        async with sem:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(h, None, type=socket.SOCK_STREAM),
                    timeout=4.0,
                )
                ips = sorted({str(info[4][0]) for info in infos if info and info[4] and is_valid_ip(str(info[4][0]))})
                if ips:
                    results[h] = ips
            except Exception:
                pass

    await asyncio.gather(*(_one(h) for h in hosts))
    return results


async def _append_job_log(job_id: str, msg: str, stats: dict[str, int] | None = None):
    async with SessionLocal() as session:
        job = await session.get(AssetCollectJob, job_id)
        if not job:
            return
        logs = list(job.logs or [])
        logs.append({"ts": to_cst_iso(datetime.now(timezone.utc)), "message": msg})
        job.logs = logs[-120:]
        if stats is not None:
            job.stats = dict(stats)
        await session.commit()


async def run_collect_job(job_id: str, cancel_event: threading.Event) -> None:
    """后台执行多源自动化资产收集，增量写入 GlobalAsset 与进度日志。"""
    stats = {
        "root_domain": 0,
        "subdomain": 0,
        "ip": 0,
        "service": 0,
        "app": 0,
        "endpoint": 0,
        "probed": 0,
        "total_upserted": 0,
    }
    try:
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if not job:
                return
            seeds_raw = list(job.seeds or [])
            sources = list(job.sources or ["crtsh", "dns", "http_probe"])
            engine_name = (job.engine or "").strip().lower()
            engine_query = (job.engine_query or "").strip()
            max_pages = max(1, min(int(job.max_pages or 3), 10))
            company_id = job.company_id
            company_name = job.company_name or ""
            companies = (await session.execute(select(AssetCompany))).scalars().all()

        parsed = parse_seed_inputs(seeds_raw)
        seed_domains = set(parsed["domains"])
        root_domains = sorted({scope_guard.root_domain(d) for d in seed_domains if d})
        discovered_hosts: set[str] = set(seed_domains)
        discovered_urls: set[str] = set(parsed["urls"])
        discovered_ips: set[str] = set(parsed["ips"])

        await _append_job_log(
            job_id,
            f"种子解析完成：{len(root_domains)} 个根域、{len(discovered_hosts)} 个主机、{len(discovered_urls)} 个 URL、{len(discovered_ips)} 个 IP",
            stats,
        )

        # 0) 种子基础入库
        async with SessionLocal() as session:
            for rd in root_domains:
                _, is_new = await upsert_global_asset(
                    session,
                    asset_type="root_domain",
                    dedup_key=rd,
                    value=rd,
                    root_domain=rd,
                    host=rd,
                    company_id=company_id,
                    company_name=company_name,
                    company_source="explicit" if company_id else "scope",
                    source="auto_collect",
                    companies_cache=companies,
                )
                if is_new:
                    stats["root_domain"] += 1
                    stats["total_upserted"] += 1
            for ip in discovered_ips:
                _, is_new = await upsert_global_asset(
                    session,
                    asset_type="ip",
                    dedup_key=ip,
                    value=ip,
                    ip=ip,
                    host=ip,
                    company_id=company_id,
                    company_name=company_name,
                    company_source="explicit" if company_id else "scope",
                    source="auto_collect",
                    companies_cache=companies,
                )
                if is_new:
                    stats["ip"] += 1
                    stats["total_upserted"] += 1
            await session.commit()

        # 1) 被动证书透明度（crt.sh）
        if "crtsh" in sources and root_domains and not cancel_event.is_set():
            await _append_job_log(job_id, f"开始被动证书透明度检索（crt.sh），共 {len(root_domains)} 个根域…", stats)
            crt_total = 0
            for rd in root_domains[:10]:
                if cancel_event.is_set():
                    break
                subs = await _fetch_crtsh_subdomains(rd)
                for s in subs:
                    discovered_hosts.add(s)
                crt_total += len(subs)
            await _append_job_log(job_id, f"crt.sh 被动检索完成，新增候选子域 {crt_total} 条", stats)

        # 2) 测绘引擎拉取（若勾选且已配置 Key）
        if "engine" in sources and engine_name and not cancel_event.is_set():
            eng = get_engine(engine_name)
            api_key = resolve_engine_key(engine_name) if eng else ""
            if eng and api_key:
                q_str = engine_query or " || ".join(f'domain="{rd}"' for rd in root_domains[:5])
                if q_str:
                    await _append_job_log(job_id, f"调用测绘引擎 {eng.display_name} 拉取资产（最多 {max_pages} 页）：{q_str[:100]}", stats)
                    base_url = resolve_engine_base_url(engine_name)
                    eng_hits = 0
                    async with SessionLocal() as session:
                        for page_no in range(1, max_pages + 1):
                            if cancel_event.is_set():
                                break
                            try:
                                er = await eng.search(api_key, q_str, page=page_no, page_size=50, base_url=base_url)
                            except Exception as exc:
                                await _append_job_log(job_id, f"测绘引擎第 {page_no} 页拉取异常：{exc}", stats)
                                break
                            if not er.results:
                                break
                            fields = er.fields or ["host", "ip", "port", "title", "domain", "org"]
                            for row in er.results:
                                rec = {fields[i]: row[i] for i in range(min(len(fields), len(row)))}
                                h_val = str(rec.get("host") or "").strip()
                                ip_val = str(rec.get("ip") or "").strip()
                                port_val = int(rec.get("port") or 0) if str(rec.get("port") or "").isdigit() else 0
                                title_val = str(rec.get("title") or "").strip()
                                url_val = h_val if h_val.startswith(("http://", "https://")) else (
                                    f"https://{h_val}" if port_val == 443 else (f"http://{h_val}" if h_val else "")
                                )
                                c = await ingest_url_into_assets(
                                    session,
                                    url=url_val,
                                    host=h_val,
                                    ip=ip_val,
                                    port=port_val,
                                    title=title_val,
                                    source=f"engine:{engine_name}",
                                    company_id=company_id,
                                    company_name=company_name,
                                    company_source="explicit" if company_id else "scope",
                                    companies_cache=companies,
                                )
                                for k, v in c.items():
                                    stats[k] += v
                                    stats["total_upserted"] += v
                                nh = scope_guard.normalize_host(h_val)
                                if nh and not is_valid_ip(nh):
                                    discovered_hosts.add(nh)
                                if url_val:
                                    discovered_urls.add(url_val)
                                eng_hits += 1
                            await session.commit()
                    await _append_job_log(job_id, f"测绘引擎 {eng.display_name} 拉取完成，处理 {eng_hits} 条记录", stats)
            else:
                await _append_job_log(job_id, f"测绘引擎 {engine_name} 未配置 API Key，已跳过测绘拉取阶段", stats)

        # 3) 平台任务资产同步
        if "task_sync" in sources and not cancel_event.is_set():
            async with SessionLocal() as session:
                synced = await sync_task_data_to_global_assets(
                    session,
                    seed_domains=set(root_domains) if root_domains else None,
                )
                await session.commit()
            for k in ASSET_TYPES:
                stats[k] += synced.get(k, 0)
                stats["total_upserted"] += synced.get(k, 0)
            await _append_job_log(job_id, f"同步平台历史任务资产完成（扫描 {synced.get('processed', 0)} 条）", stats)

        # 4) 并发 DNS 解析
        host_ip_map: dict[str, list[str]] = {}
        if "dns" in sources and discovered_hosts and not cancel_event.is_set():
            host_list = sorted(discovered_hosts)[:200]
            await _append_job_log(job_id, f"开始并发 DNS 解析（{len(host_list)} 个主机）…", stats)
            host_ip_map = await _resolve_dns_batch(host_list)
            async with SessionLocal() as session:
                for h in host_list:
                    ips_for_h = host_ip_map.get(h, [])
                    rd = scope_guard.root_domain(h)
                    _, is_new = await upsert_global_asset(
                        session,
                        asset_type="subdomain",
                        dedup_key=h,
                        value=h,
                        root_domain=rd,
                        host=h,
                        ip=ips_for_h[0] if ips_for_h else "",
                        company_id=company_id,
                        company_name=company_name,
                        company_source="explicit" if company_id else "scope",
                        source="auto_collect",
                        companies_cache=companies,
                    )
                    if is_new:
                        stats["subdomain"] += 1
                        stats["total_upserted"] += 1
                    for ip_addr in ips_for_h:
                        discovered_ips.add(ip_addr)
                        _, is_new_ip = await upsert_global_asset(
                            session,
                            asset_type="ip",
                            dedup_key=ip_addr,
                            value=ip_addr,
                            root_domain=rd,
                            host=h,
                            ip=ip_addr,
                            bound_domains=[h],
                            company_id=company_id,
                            company_name=company_name,
                            company_source="explicit" if company_id else "scope",
                            source="auto_collect",
                            companies_cache=companies,
                        )
                        if is_new_ip:
                            stats["ip"] += 1
                            stats["total_upserted"] += 1
                await session.commit()
            await _append_job_log(job_id, f"DNS 解析完成：{len(host_ip_map)} 个主机解析出 IP", stats)

        # 5) 轻量只读 HTTP/HTTPS 存活、指纹与接口发现
        if "http_probe" in sources and not cancel_event.is_set():
            probe_targets: list[str] = list(discovered_urls)
            for h in sorted(host_ip_map.keys() or discovered_hosts)[:80]:
                if not any(u.startswith((f"https://{h}", f"http://{h}")) for u in probe_targets):
                    probe_targets.append(f"https://{h}")
                    probe_targets.append(f"http://{h}")
            for ip_addr in sorted(discovered_ips)[:30]:
                if not any(ip_addr in u for u in probe_targets):
                    probe_targets.append(f"http://{ip_addr}")
            probe_targets = probe_targets[:120]

            await _append_job_log(job_id, f"开始轻量 HTTP 存活与指纹探测（{len(probe_targets)} 个候选端点）…", stats)
            sem = asyncio.Semaphore(12)
            probed_results: list[dict[str, Any]] = []

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(6.0, connect=3.5),
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; RiddleAssetProbe/1.0)"},
            ) as client:
                async def _probe_one(u: str):
                    if cancel_event.is_set():
                        return
                    async with sem:
                        if cancel_event.is_set():
                            return
                        r = await _probe_http_host(client, u)
                        if r is not None:
                            probed_results.append(r)

                await asyncio.gather(*(_probe_one(u) for u in probe_targets))

            stats["probed"] = len(probed_results)
            async with SessionLocal() as session:
                for pr in probed_results:
                    h = scope_guard.normalize_host(pr["url"])
                    ip_val = (host_ip_map.get(h) or [""])[0]
                    c = await ingest_url_into_assets(
                        session,
                        url=pr["url"],
                        host=h,
                        ip=ip_val,
                        title=pr["title"],
                        status_code=pr["status_code"],
                        technologies=pr["technologies"],
                        source="http_probe",
                        company_id=company_id,
                        company_name=company_name,
                        company_source="explicit" if company_id else "scope",
                        companies_cache=companies,
                    )
                    for k, v in c.items():
                        stats[k] += v
                        stats["total_upserted"] += v
                    for ep in pr.get("endpoints") or []:
                        c_ep = await ingest_url_into_assets(
                            session,
                            url=ep,
                            host=h,
                            ip=ip_val,
                            method="GET",
                            source="http_probe",
                            company_id=company_id,
                            company_name=company_name,
                            company_source="explicit" if company_id else "scope",
                            companies_cache=companies,
                        )
                        for k, v in c_ep.items():
                            stats[k] += v
                            stats["total_upserted"] += v
                await session.commit()
            await _append_job_log(job_id, f"HTTP 存活探测完成：存活响应 {len(probed_results)} 条", stats)

        final_status = "stopped" if cancel_event.is_set() else "done"
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.status = final_status
                job.stats = dict(stats)
                job.finished_at = datetime.now(timezone.utc)
                logs = list(job.logs or [])
                logs.append({
                    "ts": to_cst_iso(datetime.now(timezone.utc)),
                    "message": "收集任务已手动停止。" if final_status == "stopped" else f"资产自动收集完成，共新增入库 {stats['total_upserted']} 项资产。",
                })
                job.logs = logs[-120:]
                await session.commit()
    except Exception as exc:
        logger.exception("asset collect job failed: %s", job_id)
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)
                job.stats = dict(stats)
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
    finally:
        with _COLLECT_LOCK:
            _COLLECT_CANCEL.pop(job_id, None)
            _COLLECT_TASKS.pop(job_id, None)


def launch_collect_job_background(job_id: str) -> asyncio.Task:
    ev = threading.Event()
    task = asyncio.create_task(run_collect_job(job_id, ev))
    with _COLLECT_LOCK:
        _COLLECT_CANCEL[job_id] = ev
        _COLLECT_TASKS[job_id] = task
    return task
