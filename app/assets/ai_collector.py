"""AI 自然语言自主资产收集 Agent。

用户以自然语言描述收集意图（如"收集某高校 sit.edu.cn 相关教务与门户资产并识别指纹"），
Agent 自主思考、制定测绘与探测策略，多轮调用真实只读收集工具（主体范围创建、crt.sh 证书透明度、
6 大空间测绘引擎、并发 DNS 解析、轻量 HTTP 存活/指纹/接口探测、平台历史资产同步），
将结果幂等落盘到双图全局资产真值库（GlobalAsset），并实时记录思考轨迹与最终资产摸排报告。
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets import collector_service as svc
from app.db.models import AssetCollectJob, AssetCompany, GlobalAsset, to_cst_iso
from app.db.session import SessionLocal
from app.engines import get_engine, list_engines
from app.fusion import scope_guard
from app.llm.client import LLMClient, LLMError
from app.llm.usage import clear_usage, usage_snapshot
from app.settings_service import (
    public_settings_view,
    resolve_engine_base_url,
    resolve_engine_key,
    resolve_llm_providers,
    resolve_llm_runtime_mode,
)

logger = logging.getLogger("riddle.ai_collector")

# ── AI 资产收集专用工具集（全部只读/落盘资产库，无破坏性操作） ──
AI_COLLECT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ensure_asset_company",
            "description": "创建或更新企业/高校归属主体并配置范围规则（domain/ip/cidr/icp/keyword），自动认领匹配的资产。",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "企业或高校名称"},
                    "scope_rules": {
                        "type": "array",
                        "description": "范围规则列表",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string", "enum": ["domain", "ip", "cidr", "icp", "keyword"]},
                                "value": {"type": "string"},
                            },
                            "required": ["kind", "value"],
                        },
                    },
                    "notes": {"type": "string", "description": "授权或收集备注"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_crtsh_subdomains",
            "description": "通过被动证书透明度日志（crt.sh）收集根域名下的历史与在用子域名，并自动入库全局资产图。",
            "parameters": {
                "type": "object",
                "properties": {
                    "root_domain": {"type": "string", "description": "根域名，如 example.edu.cn"},
                },
                "required": ["root_domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_mapping_engine",
            "description": "调用已配置 API Key 的空间测绘引擎（fofa/quake/hunter/zoomeye/shodan/censys）检索资产，结果自动拆解落盘到全局资产库。",
            "parameters": {
                "type": "object",
                "properties": {
                    "engine": {"type": "string", "description": "测绘引擎名：fofa / quake / hunter / zoomeye / shodan / censys"},
                    "query": {"type": "string", "description": "对应引擎的测绘查询语法"},
                    "max_pages": {"type": "integer", "description": "最大翻页数（1-5），默认 2"},
                },
                "required": ["engine", "query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "resolve_dns_hosts",
            "description": "对一组域名/子域名进行并发 DNS 解析，建立 subdomain -> IP 关系并计算 /24 C 段入库。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hosts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "待解析的主机名列表（单次最多 80 个）",
                    },
                },
                "required": ["hosts"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_http_services",
            "description": "对一组 URL 或主机进行轻量只读 HTTP/HTTPS 存活探测、标题与技术栈指纹识别及同站接口发现，自动入库 service/app/endpoint。",
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "待探测的 URL 或域名列表（单次最多 40 个）",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sync_existing_riddle_assets",
            "description": "将知蠹 Riddle 既有挖掘任务中的 Target 与实证流量端点同步入全局双图资产库。",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain_filter": {"type": "string", "description": "可选：仅同步匹配该根域名的记录，留空同步全部"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_collected_assets",
            "description": "查询当前全局双图资产库中已落盘的资产（支持 DSL 过滤），用于复盘覆盖情况与查漏补缺。",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_type": {"type": "string", "description": "all / root_domain / subdomain / ip / service / app / endpoint"},
                    "q": {"type": "string", "description": "DSL 过滤或关键字，如 domain:edu.cn status:200"},
                    "limit": {"type": "integer", "description": "返回条数（1-40），默认 25"},
                },
            },
        },
    },
]


def _build_llm(usage_key: str | None = None) -> LLMClient | None:
    providers = resolve_llm_providers(None)
    if not providers:
        return None
    pool_mode = resolve_llm_runtime_mode(None) == "pool" or len(providers) > 1
    try:
        return LLMClient(providers=providers, pool_mode=pool_mode, usage_key=usage_key)
    except Exception as exc:
        logger.warning("build ai collector llm failed: %s", exc)
        return None


def _configured_engines_summary() -> list[dict[str, Any]]:
    pub = public_settings_view()
    ep = pub.get("engines") or {}
    return [
        {
            "name": e["name"],
            "display_name": e["display_name"],
            "key_set": bool((ep.get(e["name"]) or {}).get("key_set")),
        }
        for e in list_engines()
    ]


def _extract_json_block(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if not raw:
        return {}
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw, re.I)
    candidate = fence.group(1).strip() if fence else raw
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start >= 0 and end > start:
        candidate = candidate[start : end + 1]
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _fallback_plan(prompt: str, engines: list[dict[str, Any]]) -> dict[str, Any]:
    """当模型未返回标准 JSON 时的确定性降级规划。"""
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", prompt or "")
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", prompt or "")
    seeds = list(dict.fromkeys([*domain_matches, *ip_matches]))[:20]
    configured = [e["name"] for e in engines if e.get("key_set")]
    rec_engine = configured[0] if configured else ""
    queries = [f'domain="{scope_guard.root_domain(d)}"' for d in domain_matches[:3] if scope_guard.root_domain(d)]
    return {
        "task_name": f"AI 资产收集 · {(seeds[0] if seeds else (prompt or '自然语言任务')[:24])}",
        "summary": "依据用户输入自动提取初始种子并执行多源资产发现、DNS 解析与 HTTP 指纹探测。",
        "company_name": "",
        "scope_rules": [{"kind": "domain", "value": scope_guard.root_domain(d)} for d in domain_matches[:5] if scope_guard.root_domain(d)],
        "seeds": seeds,
        "recommended_engine": rec_engine,
        "queries": list(dict.fromkeys(queries)),
        "steps": [
            "解析目标范围并建立/匹配归属主体",
            "通过证书透明度（crt.sh）与已配置测绘引擎扩面收集子域与服务",
            "执行并发 DNS 解析归并 IP 与 C 段",
            "执行轻量只读 HTTP 存活与指纹探测，梳理高价值资产并汇总报告",
        ],
        "reasoning": "基于提示词提取目标域名与网段，优先使用已配置的测绘与被动侦察能力。",
    }


async def plan_collection_from_prompt(
    prompt: str,
    session: AsyncSession,
    preferred_engine: str = "",
) -> dict[str, Any]:
    """调用大模型理解用户自然语言资产收集需求，输出结构化思考与执行计划。"""
    engines = _configured_engines_summary()
    companies = (await session.execute(select(AssetCompany).order_by(desc(AssetCompany.updated_at)).limit(30))).scalars().all()
    comp_names = [c.name for c in companies]

    usage_key = f"ai-plan-{uuid.uuid4().hex[:8]}"
    llm = _build_llm(usage_key=usage_key)
    if llm is None:
        raise RuntimeError("尚未配置大模型 API Key，请先前往「模型与多角色路由」或「系统设置」完成配置")

    sys_prompt = (
        "你是知蠹 Riddle 的 AI 资产收集规划专家。用户会用自然语言描述想要收集的授权目标资产。\n"
        "请你仔细思考目标边界、归属主体、初始种子、应选用的测绘引擎与精准语法，输出严格 JSON（不要附加多余解释）：\n"
        "{\n"
        '  "task_name": "简短清晰的任务标题（25字内）",\n'
        '  "summary": "一句话概述本次收集策略",\n'
        '  "company_name": "识别出的企业或高校名称，无法确定则留空",\n'
        '  "scope_rules": [{"kind": "domain|ip|cidr|icp|keyword", "value": "..."}],\n'
        '  "seeds": ["提取的根域名、URL、IP 或 CIDR"],\n'
        '  "recommended_engine": "从已配置 key_set=true 的引擎中选择一个，无可用则留空",\n'
        '  "queries": ["针对所选测绘引擎构造的 1~3 条精准查询语法"],\n'
        '  "steps": ["按顺序列出 3~5 个执行步骤"],\n'
        '  "reasoning": "简要说明你的思考依据与范围收敛策略"\n'
        "}"
    )
    user_msg = (
        f"【用户自然语言需求】\n{prompt.strip()}\n\n"
        f"【当前测绘引擎配置状态】\n{json.dumps(engines, ensure_ascii=False)}\n"
        f"【用户偏好引擎】{preferred_engine or '自动选择'}\n"
        f"【平台已有主体列表】{json.dumps(comp_names, ensure_ascii=False)}"
    )
    try:
        msg = await asyncio.to_thread(
            llm.chat,
            [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_msg},
            ],
            None,
            None,
            0.2,
        )
        raw_content = str(getattr(msg, "content", "") or "")
        parsed = _extract_json_block(raw_content)
        fb = _fallback_plan(prompt, engines)
        merged = {
            "task_name": str(parsed.get("task_name") or fb["task_name"])[:120],
            "summary": str(parsed.get("summary") or fb["summary"]),
            "company_name": str(parsed.get("company_name") or fb["company_name"])[:120],
            "scope_rules": svc.normalize_scope_rules(parsed.get("scope_rules")) or fb["scope_rules"],
            "seeds": [str(x).strip() for x in (parsed.get("seeds") or fb["seeds"]) if str(x).strip()][:50],
            "recommended_engine": str(parsed.get("recommended_engine") or preferred_engine or fb["recommended_engine"]).strip().lower(),
            "queries": [str(x).strip() for x in (parsed.get("queries") or fb["queries"]) if str(x).strip()][:5],
            "steps": [str(x).strip() for x in (parsed.get("steps") or fb["steps"]) if str(x).strip()][:8],
            "reasoning": str(parsed.get("reasoning") or getattr(msg, "reasoning_content", "") or fb["reasoning"]),
        }
        return merged
    finally:
        clear_usage(usage_key)


# ── AI 收集执行状态辅助函数 ───────────────────────────────────
async def _record_trace(
    job_id: str,
    *,
    kind: str,
    title: str,
    detail: str = "",
    tool_name: str = "",
    duration_ms: int = 0,
    stats: dict[str, int] | None = None,
    log_msg: str = "",
) -> None:
    async with SessionLocal() as session:
        job = await session.get(AssetCollectJob, job_id)
        if not job:
            return
        now_iso = to_cst_iso(datetime.now(timezone.utc))
        trace = list(job.ai_trace or [])
        trace.append({
            "ts": now_iso,
            "kind": kind,
            "title": title,
            "detail": detail[:12000],
            "tool_name": tool_name,
            "duration_ms": int(duration_ms or 0),
        })
        job.ai_trace = trace[-150:]

        if log_msg or title:
            logs = list(job.logs or [])
            logs.append({"ts": now_iso, "message": log_msg or title})
            job.logs = logs[-150:]

        if stats is not None:
            job.stats = dict(stats)
        await session.commit()


class _JobRuntimeContext:
    def __init__(self, job_id: str, company_id: str | None, company_name: str):
        self.job_id = job_id
        self.company_id = company_id
        self.company_name = company_name
        self.stats: dict[str, int] = {
            "root_domain": 0,
            "subdomain": 0,
            "ip": 0,
            "service": 0,
            "app": 0,
            "endpoint": 0,
            "probed": 0,
            "total_upserted": 0,
        }

    def add_counts(self, counts: dict[str, int]):
        for k in svc.ASSET_TYPES:
            v = int(counts.get(k) or 0)
            if v > 0:
                self.stats[k] += v
                self.stats["total_upserted"] += v


async def _exec_ai_tool(
    ctx: _JobRuntimeContext,
    tool_name: str,
    args: dict[str, Any],
    cancel_event: threading.Event,
) -> str:
    if tool_name == "ensure_asset_company":
        name = str(args.get("name") or "").strip()
        if not name:
            return "错误：主体名称 name 不能为空。"
        rules = svc.normalize_scope_rules(args.get("scope_rules"))
        notes = str(args.get("notes") or "").strip()
        nkey = svc.normalize_company_key(name)
        async with SessionLocal() as session:
            comp = (await session.execute(select(AssetCompany).where(AssetCompany.nkey == nkey))).scalar_one_or_none()
            if comp is None:
                comp = AssetCompany(name=name[:200], nkey=nkey[:200], scope_rules=rules, notes=notes)
                session.add(comp)
                await session.flush()
                created = True
            else:
                if rules:
                    merged_rules = svc.normalize_scope_rules([*(comp.scope_rules or []), *rules])
                    comp.scope_rules = merged_rules
                if notes and not comp.notes:
                    comp.notes = notes
                comp.updated_at = datetime.now(timezone.utc)
                created = False
            claimed = await svc.claim_assets_for_company(session, comp)
            job = await session.get(AssetCollectJob, ctx.job_id)
            if job:
                job.company_id = comp.id
                job.company_name = comp.name
            await session.commit()
            ctx.company_id = comp.id
            ctx.company_name = comp.name
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "company_id": ctx.company_id,
                "company_name": ctx.company_name,
                "rules_count": len(rules),
                "claimed_existing_assets": claimed,
            },
            ensure_ascii=False,
        )

    if tool_name == "query_crtsh_subdomains":
        rd = scope_guard.root_domain(str(args.get("root_domain") or "").strip())
        if not rd:
            return "错误：无效的根域名。"
        subs = await svc._fetch_crtsh_subdomains(rd)
        async with SessionLocal() as session:
            companies = (await session.execute(select(AssetCompany))).scalars().all()
            _, is_new = await svc.upsert_global_asset(
                session,
                asset_type="root_domain",
                dedup_key=rd,
                value=rd,
                root_domain=rd,
                host=rd,
                company_id=ctx.company_id,
                company_name=ctx.company_name,
                company_source="explicit" if ctx.company_id else "scope",
                source="ai_crtsh",
                companies_cache=companies,
            )
            if is_new:
                ctx.add_counts({"root_domain": 1})
            new_sub = 0
            for h in subs:
                _, is_new_h = await svc.upsert_global_asset(
                    session,
                    asset_type="subdomain",
                    dedup_key=h,
                    value=h,
                    root_domain=rd,
                    host=h,
                    company_id=ctx.company_id,
                    company_name=ctx.company_name,
                    company_source="explicit" if ctx.company_id else "scope",
                    source="ai_crtsh",
                    companies_cache=companies,
                )
                if is_new_h:
                    new_sub += 1
            if new_sub:
                ctx.add_counts({"subdomain": new_sub})
            await session.commit()
        return json.dumps(
            {
                "root_domain": rd,
                "discovered_count": len(subs),
                "newly_persisted": new_sub,
                "sample_subdomains": subs[:40],
            },
            ensure_ascii=False,
        )

    if tool_name == "query_mapping_engine":
        eng_name = str(args.get("engine") or "").strip().lower()
        q_str = str(args.get("query") or "").strip()
        max_pages = max(1, min(int(args.get("max_pages") or 2), 5))
        eng = get_engine(eng_name)
        if eng is None:
            return f"错误：不支持的测绘引擎 {eng_name}。"
        api_key = resolve_engine_key(eng_name)
        if not api_key:
            return f"跳过：测绘引擎 {eng.display_name} 尚未配置 API Key，请改用 crt.sh/DNS/HTTP 或其他已配 Key 引擎。"
        if not q_str:
            return "错误：query 语法不能为空。"

        base_url = resolve_engine_base_url(eng_name)
        samples: list[dict[str, Any]] = []
        total_rows = 0
        async with SessionLocal() as session:
            companies = (await session.execute(select(AssetCompany))).scalars().all()
            for page_no in range(1, max_pages + 1):
                if cancel_event.is_set():
                    break
                try:
                    er = await eng.search(api_key, q_str, page=page_no, page_size=50, base_url=base_url)
                except Exception as exc:
                    return f"测绘引擎 {eng.display_name} 请求失败：{exc}"
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
                    c = await svc.ingest_url_into_assets(
                        session,
                        url=url_val,
                        host=h_val,
                        ip=ip_val,
                        port=port_val,
                        title=title_val,
                        source=f"ai_engine:{eng_name}",
                        company_id=ctx.company_id,
                        company_name=ctx.company_name,
                        company_source="explicit" if ctx.company_id else "scope",
                        companies_cache=companies,
                    )
                    ctx.add_counts(c)
                    total_rows += 1
                    if len(samples) < 25:
                        samples.append({"host": h_val, "ip": ip_val, "port": port_val, "title": title_val[:60]})
                await session.commit()
        return json.dumps(
            {
                "engine": eng.display_name,
                "query": q_str,
                "total_rows": total_rows,
                "samples": samples,
            },
            ensure_ascii=False,
        )

    if tool_name == "resolve_dns_hosts":
        raw_hosts = [scope_guard.normalize_host(str(h)) for h in (args.get("hosts") or [])]
        hosts = list(dict.fromkeys([h for h in raw_hosts if h and not svc.is_valid_ip(h)]))[:80]
        if not hosts:
            return "未提供可解析的有效域名。"
        resolved = await svc._resolve_dns_batch(hosts)
        c_segments: set[str] = set()
        async with SessionLocal() as session:
            companies = (await session.execute(select(AssetCompany))).scalars().all()
            for h, ips in resolved.items():
                rd = scope_guard.root_domain(h)
                _, is_new_sub = await svc.upsert_global_asset(
                    session,
                    asset_type="subdomain",
                    dedup_key=h,
                    value=h,
                    root_domain=rd,
                    host=h,
                    ip=ips[0] if ips else "",
                    company_id=ctx.company_id,
                    company_name=ctx.company_name,
                    company_source="explicit" if ctx.company_id else "scope",
                    source="ai_dns",
                    companies_cache=companies,
                )
                if is_new_sub:
                    ctx.add_counts({"subdomain": 1})
                for ip_addr in ips:
                    cseg = svc.calc_c_segment(ip_addr)
                    if cseg:
                        c_segments.add(cseg)
                    _, is_new_ip = await svc.upsert_global_asset(
                        session,
                        asset_type="ip",
                        dedup_key=ip_addr,
                        value=ip_addr,
                        root_domain=rd,
                        host=h,
                        ip=ip_addr,
                        bound_domains=[h],
                        company_id=ctx.company_id,
                        company_name=ctx.company_name,
                        company_source="explicit" if ctx.company_id else "scope",
                        source="ai_dns",
                        companies_cache=companies,
                    )
                    if is_new_ip:
                        ctx.add_counts({"ip": 1})
            await session.commit()
        return json.dumps(
            {
                "input_hosts": len(hosts),
                "resolved_count": len(resolved),
                "c_segments": sorted(c_segments)[:20],
                "mapping_sample": {k: v for k, v in list(resolved.items())[:25]},
            },
            ensure_ascii=False,
        )

    if tool_name == "probe_http_services":
        raw_targets = [str(x).strip() for x in (args.get("targets") or []) if str(x).strip()]
        probe_urls: list[str] = []
        seen_u: set[str] = set()
        for item in raw_targets[:40]:
            if item.startswith(("http://", "https://")):
                cands = [item]
            else:
                cands = [f"https://{item}", f"http://{item}"]
            for u in cands:
                if u not in seen_u:
                    seen_u.add(u)
                    probe_urls.append(u)
        probe_urls = probe_urls[:50]
        if not probe_urls:
            return "未提供可探测的目标。"

        sem = asyncio.Semaphore(10)
        alive: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(6.0, connect=3.5),
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RiddleAIAssetProbe/1.0)"},
        ) as client:
            async def _one(u: str):
                if cancel_event.is_set():
                    return
                async with sem:
                    if cancel_event.is_set():
                        return
                    r = await svc._probe_http_host(client, u)
                    if r is not None:
                        alive.append(r)

            await asyncio.gather(*(_one(u) for u in probe_urls))

        ctx.stats["probed"] += len(alive)
        async with SessionLocal() as session:
            companies = (await session.execute(select(AssetCompany))).scalars().all()
            for pr in alive:
                h = scope_guard.normalize_host(pr["url"])
                c = await svc.ingest_url_into_assets(
                    session,
                    url=pr["url"],
                    host=h,
                    title=pr["title"],
                    status_code=pr["status_code"],
                    technologies=pr["technologies"],
                    source="ai_http_probe",
                    company_id=ctx.company_id,
                    company_name=ctx.company_name,
                    company_source="explicit" if ctx.company_id else "scope",
                    companies_cache=companies,
                )
                ctx.add_counts(c)
                for ep in (pr.get("endpoints") or [])[:10]:
                    cep = await svc.ingest_url_into_assets(
                        session,
                        url=ep,
                        host=h,
                        method="GET",
                        source="ai_http_probe",
                        company_id=ctx.company_id,
                        company_name=ctx.company_name,
                        company_source="explicit" if ctx.company_id else "scope",
                        companies_cache=companies,
                    )
                    ctx.add_counts(cep)
            await session.commit()

        return json.dumps(
            {
                "probed_candidates": len(probe_urls),
                "alive_count": len(alive),
                "alive_services": [
                    {
                        "url": r["url"],
                        "status": r["status_code"],
                        "title": r["title"][:60],
                        "tech": r["technologies"][:5],
                        "endpoints_found": len(r.get("endpoints") or []),
                    }
                    for r in alive[:25]
                ],
            },
            ensure_ascii=False,
        )

    if tool_name == "sync_existing_riddle_assets":
        dom = scope_guard.root_domain(str(args.get("domain_filter") or "").strip())
        async with SessionLocal() as session:
            synced = await svc.sync_task_data_to_global_assets(
                session,
                seed_domains={dom} if dom else None,
            )
            await session.commit()
        ctx.add_counts(synced)
        return json.dumps({"ok": True, "synced": synced}, ensure_ascii=False)

    if tool_name == "query_collected_assets":
        atype = str(args.get("asset_type") or "all").strip().lower()
        q = str(args.get("q") or "").strip()
        lim = max(1, min(int(args.get("limit") or 25), 40))
        async with SessionLocal() as session:
            stmt = select(GlobalAsset)
            if atype in svc.ASSET_TYPES:
                stmt = stmt.where(GlobalAsset.asset_type == atype)
            if ctx.company_id:
                stmt = stmt.where(GlobalAsset.company_id == ctx.company_id)
            rows = (await session.execute(stmt.order_by(desc(GlobalAsset.last_seen)).limit(300))).scalars().all()
            filtered = svc.filter_assets_by_dsl(rows, q)[:lim]
            return json.dumps(
                [
                    {
                        "type": r.asset_type,
                        "value": r.value,
                        "ip": r.ip,
                        "port": r.port,
                        "status": r.status_code,
                        "title": r.title[:50],
                        "tech": (r.technologies or [])[:4],
                    }
                    for r in filtered
                ],
                ensure_ascii=False,
            )

    return f"未知工具：{tool_name}"


async def run_ai_collect_job(
    job_id: str,
    cancel_event: threading.Event,
    *,
    max_rounds: int = 8,
    preferred_engine: str = "",
) -> None:
    """后台运行 AI 自然语言自主资产收集主循环。"""
    usage_key = f"ai-collect-{job_id}"
    try:
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if not job:
                return
            prompt = (job.prompt or "").strip()
            ctx = _JobRuntimeContext(job_id, job.company_id, job.company_name or "")

        llm = _build_llm(usage_key=usage_key)
        if llm is None:
            await _record_trace(
                job_id,
                kind="error",
                title="未配置可用大模型 API Key",
                detail="请先前往「模型与多角色路由」或「系统设置」配置大模型后再启动 AI 资产收集。",
            )
            async with SessionLocal() as session:
                job = await session.get(AssetCollectJob, job_id)
                if job:
                    job.status = "failed"
                    job.error = "未配置可用大模型 API Key"
                    job.finished_at = datetime.now(timezone.utc)
                    await session.commit()
            return

        engines_info = _configured_engines_summary()
        configured_engine_names = [e["name"] for e in engines_info if e["key_set"]]

        # 先做一次结构化意图规划落盘，便于前端展示 AI 计划卡片
        await _record_trace(job_id, kind="thinking", title="AI 正在理解自然语言需求并制定收集计划…")
        async with SessionLocal() as session:
            try:
                plan = await plan_collection_from_prompt(prompt, session, preferred_engine=preferred_engine)
            except Exception:
                plan = _fallback_plan(prompt, engines_info)
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.ai_plan = plan
                if not job.name or job.name == "AI 资产收集":
                    job.name = str(plan.get("task_name") or job.name)[:200]
                if plan.get("seeds"):
                    job.seeds = list(plan["seeds"])[:100]
                await session.commit()

        await _record_trace(
            job_id,
            kind="thinking",
            title=f"收集规划就绪：{plan.get('summary', '')}",
            detail=json.dumps(plan, ensure_ascii=False, indent=2),
        )

        system_prompt = (
            "你是知蠹 Riddle 的 AI 自主资产收集 Agent，专门负责授权范围内的攻击面测绘与资产整理。\n"
            "你的工作流程：\n"
            "1. 仔细理解用户自然语言意图，若识别出企业/高校名称与范围，优先调用 `ensure_asset_company` 建立归属主体。\n"
            "2. 合理组合工具收集资产：\n"
            "   - 对根域名调用 `query_crtsh_subdomains` 被动发现子域名；\n"
            "   - 若有已配置 Key 的测绘引擎，调用 `query_mapping_engine` 构造精准语法扩面；\n"
            "   - 对发现的子域名调用 `resolve_dns_hosts` 补全 IP 与 C 段；\n"
            "   - 对高价值主机/域名调用 `probe_http_services` 获取存活状态码、标题、技术栈指纹和页面接口；\n"
            "   - 必要时调用 `sync_existing_riddle_assets` 合并平台既有资产。\n"
            "3. 每一轮工具返回后，分析新发现的资产并决定下一步（例如把新发现的子域做 DNS + HTTP 探活），避免重复调用相同参数。\n"
            "4. 信息充分或到达收尾轮时，输出结构化的 Markdown《AI 资产摸排总结报告》，包含：收集范围与主体、各类资产统计、高价值 Web/管理后台清单、技术栈与 C 段分布、以及下一步建议重点挖掘的目标。"
        )
        user_init = (
            f"【用户自然语言收集指令】\n{prompt}\n\n"
            f"【初始规划参考】\n{json.dumps(plan, ensure_ascii=False)}\n\n"
            f"【当前已配置 API Key 的测绘引擎】{json.dumps(configured_engine_names, ensure_ascii=False)}\n"
            f"【默认绑定主体】{ctx.company_name or '未指定（如从需求中识别出组织请调用 ensure_asset_company 创建）'}"
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_init},
        ]

        safe_rounds = max(3, min(int(max_rounds or 8), 12))
        final_summary = ""

        for round_idx in range(safe_rounds):
            if cancel_event.is_set():
                await _record_trace(job_id, kind="summary", title="已收到停止指令，提前结束收集。", stats=ctx.stats)
                break

            last_round = round_idx == safe_rounds - 1
            call_messages = messages
            if last_round:
                call_messages = messages + [{
                    "role": "user",
                    "content": "这是最终总结轮，请不要再调用任何工具，直接基于本次所有工具返回结果输出清晰的 Markdown《AI 资产摸排总结报告》。",
                }]

            msg = await asyncio.to_thread(
                llm.chat,
                call_messages,
                AI_COLLECT_TOOLS,
                "none" if last_round else "auto",
                0.25,
            )

            if cancel_event.is_set():
                await _record_trace(job_id, kind="summary", title="已手动停止当前 AI 资产收集任务。", stats=ctx.stats)
                break

            reasoning = str(getattr(msg, "reasoning_content", "") or "").strip()
            content = str(getattr(msg, "content", "") or "").strip()
            tool_calls = getattr(msg, "tool_calls", None) or []

            if reasoning:
                await _record_trace(
                    job_id,
                    kind="thinking",
                    title=f"第 {round_idx + 1} 轮推理思考",
                    detail=reasoning,
                    stats=ctx.stats,
                )

            if tool_calls and not last_round:
                if content:
                    await _record_trace(
                        job_id,
                        kind="thinking",
                        title=f"第 {round_idx + 1} 轮决策：{content[:100]}",
                        detail=content,
                        stats=ctx.stats,
                    )

                messages.append({
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                        }
                        for tc in tool_calls
                    ],
                })

                for tc in tool_calls:
                    if cancel_event.is_set():
                        break
                    t_name = tc.function.name
                    raw_args = tc.function.arguments or "{}"
                    try:
                        parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                    except Exception:
                        parsed_args = {}

                    await _record_trace(
                        job_id,
                        kind="tool_use",
                        title=f"调用收集工具 `{t_name}`",
                        detail=json.dumps(parsed_args, ensure_ascii=False, indent=2),
                        tool_name=t_name,
                        stats=ctx.stats,
                    )

                    t0 = time.perf_counter()
                    try:
                        tool_out = await _exec_ai_tool(ctx, t_name, parsed_args, cancel_event)
                    except Exception as exc:
                        tool_out = f"工具执行异常：{exc}"
                    dur_ms = int((time.perf_counter() - t0) * 1000)

                    await _record_trace(
                        job_id,
                        kind="tool_result",
                        title=f"`{t_name}` 完成（{dur_ms}ms · 累计新增 {ctx.stats['total_upserted']} 项资产）",
                        detail=tool_out,
                        tool_name=t_name,
                        duration_ms=dur_ms,
                        stats=ctx.stats,
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": tool_out[:10000],
                    })
                continue

            final_summary = content or "AI 资产收集已完成，请在双图资产库查看新增资产。"
            await _record_trace(
                job_id,
                kind="summary",
                title="AI 资产摸排总结已生成",
                detail=final_summary,
                stats=ctx.stats,
            )
            break

        final_status = "stopped" if cancel_event.is_set() else "done"
        snap = usage_snapshot(usage_key)
        ctx.stats["input_tokens"] = int(snap.get("prompt_tokens") or 0)
        ctx.stats["output_tokens"] = int(snap.get("completion_tokens") or 0)

        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.status = final_status
                job.stats = dict(ctx.stats)
                job.ai_summary = final_summary or job.ai_summary
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
    except (LLMError, RuntimeError) as exc:
        await _record_trace(job_id, kind="error", title=f"模型调用失败：{exc}")
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
    except Exception as exc:
        logger.exception("ai collect job failed: %s", job_id)
        await _record_trace(job_id, kind="error", title=f"AI 收集任务异常：{exc}")
        async with SessionLocal() as session:
            job = await session.get(AssetCollectJob, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
    finally:
        clear_usage(usage_key)
        with svc._COLLECT_LOCK:
            svc._COLLECT_CANCEL.pop(job_id, None)
            svc._COLLECT_TASKS.pop(job_id, None)


def launch_ai_collect_job_background(
    job_id: str,
    *,
    max_rounds: int = 8,
    preferred_engine: str = "",
) -> asyncio.Task:
    ev = threading.Event()
    task = asyncio.create_task(
        run_ai_collect_job(job_id, ev, max_rounds=max_rounds, preferred_engine=preferred_engine)
    )
    with svc._COLLECT_LOCK:
        svc._COLLECT_CANCEL[job_id] = ev
        svc._COLLECT_TASKS[job_id] = task
    return task
