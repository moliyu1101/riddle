"""双图全局资产库与自动化资产收集 API。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.deepen import clamp_deepen_cap
from app.agents.prompts import normalize_src_type
from app.api.tasks import _clamp_task_concurrency, _task_to_dto
from app.assets import ai_collector
from app.assets import collector_service as svc
from app.db.models import AssetCollectJob, AssetCompany, GlobalAsset, Task, TaskEvent, to_cst_iso
from app.db.session import get_session
from app.engines import get_engine, list_engines
from app.fusion import graphs as fusion_graphs
from app.orchestrator import manager
from app.settings_service import (
    effective_settings,
    public_settings_view,
    refresh_cache,
    resolve_engine_key,
    resolve_llm_providers,
)
from app.tools.guard import normalize_guard_ops

router = APIRouter(prefix="/api/assets", tags=["assets"])


# ── Pydantic 请求模型 ─────────────────────────────────────────
class CompanyScopeRuleIn(BaseModel):
    kind: str
    value: str


class CompanyCreateRequest(BaseModel):
    name: str
    scope_rules: list[CompanyScopeRuleIn] = Field(default_factory=list)
    notes: str = ""


class CompanyPatchRequest(BaseModel):
    name: str | None = None
    scope_rules: list[CompanyScopeRuleIn] | None = None
    notes: str | None = None


class ManualAssetImportRequest(BaseModel):
    seeds: list[str] = Field(default_factory=list)
    seeds_text: str = ""
    company_id: str | None = None


class BatchDeleteAssetsRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


class SyncFromTasksRequest(BaseModel):
    task_id: str | None = None


class CollectJobCreateRequest(BaseModel):
    name: str = ""
    seeds: list[str] = Field(default_factory=list)
    seeds_text: str = ""
    company_id: str | None = None
    sources: list[str] = Field(default_factory=lambda: ["crtsh", "dns", "http_probe"])
    engine: str = ""
    engine_query: str = ""
    max_pages: int = Field(default=3, ge=1, le=10)


class AICollectPlanRequest(BaseModel):
    prompt: str
    preferred_engine: str = ""


class AICollectJobCreateRequest(BaseModel):
    prompt: str
    name: str = ""
    company_id: str | None = None
    preferred_engine: str = ""
    max_rounds: int = Field(default=8, ge=3, le=12)


class AssetsToTaskRequest(BaseModel):
    name: str = ""
    asset_ids: list[str] = Field(default_factory=list)
    company_id: str | None = None
    src_type: str = "edusrc"
    concurrency: int | None = None
    guard_ops: list[str] | None = None
    start_immediately: bool = True


# ── DTO 转换 ──────────────────────────────────────────────────
def _company_dto(c: AssetCompany, asset_count: int = 0) -> dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "nkey": c.nkey,
        "scope_rules": c.scope_rules or [],
        "notes": c.notes or "",
        "asset_count": asset_count,
        "created_at": to_cst_iso(c.created_at),
        "updated_at": to_cst_iso(c.updated_at),
    }


def _asset_dto(a: GlobalAsset) -> dict[str, Any]:
    return {
        "id": a.id,
        "asset_type": a.asset_type,
        "dedup_key": a.dedup_key,
        "value": a.value,
        "company_id": a.company_id,
        "company_name": a.company_name or "",
        "company_source": a.company_source or "scope",
        "root_domain": a.root_domain or "",
        "host": a.host or "",
        "ip": a.ip or "",
        "c_segment": a.c_segment or "",
        "port": int(a.port or 0),
        "protocol": a.protocol or "",
        "status_code": int(a.status_code or 0),
        "title": a.title or "",
        "technologies": a.technologies or [],
        "open_ports": a.open_ports or [],
        "bound_domains": a.bound_domains or [],
        "method": a.method or "",
        "params": a.params or [],
        "source": a.source or "",
        "task_ids": a.task_ids or [],
        "first_seen": to_cst_iso(a.first_seen),
        "last_seen": to_cst_iso(a.last_seen),
    }


def _job_dto(j: AssetCollectJob) -> dict[str, Any]:
    return {
        "id": j.id,
        "name": j.name or "资产自动收集",
        "mode": getattr(j, "mode", None) or "manual",
        "prompt": getattr(j, "prompt", None) or "",
        "seeds": j.seeds or [],
        "company_id": j.company_id,
        "company_name": j.company_name or "",
        "sources": j.sources or [],
        "engine": j.engine or "",
        "engine_query": j.engine_query or "",
        "max_pages": int(j.max_pages or 3),
        "status": j.status or "running",
        "running": svc.is_collect_job_running(j.id),
        "stats": j.stats or {},
        "logs": j.logs or [],
        "ai_plan": getattr(j, "ai_plan", None) or {},
        "ai_trace": getattr(j, "ai_trace", None) or [],
        "ai_summary": getattr(j, "ai_summary", None) or "",
        "error": j.error or "",
        "created_at": to_cst_iso(j.created_at),
        "finished_at": to_cst_iso(j.finished_at),
    }


# ── 总览与六类资产列表 ────────────────────────────────────────
@router.get("/overview")
async def assets_overview(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    company_count = (await session.execute(select(func.count()).select_from(AssetCompany))).scalar() or 0
    rows = (
        await session.execute(
            select(GlobalAsset.asset_type, func.count()).group_by(GlobalAsset.asset_type)
        )
    ).all()
    counts: dict[str, int] = {k: 0 for k in svc.ASSET_TYPES}
    for atype, cnt in rows:
        counts[str(atype)] = int(cnt or 0)
    counts["company"] = int(company_count)
    total_assets = sum(counts[k] for k in svc.ASSET_TYPES)

    running_jobs = (
        await session.execute(
            select(func.count()).select_from(AssetCollectJob).where(AssetCollectJob.status == "running")
        )
    ).scalar() or 0

    pub = public_settings_view()
    engines_pub = pub.get("engines") or {}
    engines = [
        {
            "name": eng["name"],
            "display_name": eng["display_name"],
            "key_set": bool((engines_pub.get(eng["name"]) or {}).get("key_set")),
        }
        for eng in list_engines()
    ]
    return {
        "counts": counts,
        "total_assets": total_assets,
        "running_jobs": int(running_jobs),
        "engines": engines,
        "llm_ready": bool(resolve_llm_providers(None)),
    }


@router.get("")
async def list_global_assets(
    asset_type: str = Query("all"),
    company_id: str | None = Query(None),
    q: str = Query(""),
    limit: int = Query(100, ge=1, le=300),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(GlobalAsset)
    if asset_type and asset_type != "all":
        if asset_type not in svc.ASSET_TYPES:
            raise HTTPException(status_code=400, detail=f"无效的资产类型：{asset_type}")
        stmt = stmt.where(GlobalAsset.asset_type == asset_type)
    if company_id and company_id != "all":
        stmt = stmt.where(GlobalAsset.company_id == company_id)

    all_rows = (await session.execute(stmt.order_by(desc(GlobalAsset.last_seen)).limit(2000))).scalars().all()
    filtered = svc.filter_assets_by_dsl(all_rows, q)
    total = len(filtered)
    page_rows = filtered[offset : offset + limit]
    return {
        "items": [_asset_dto(r) for r in page_rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page_rows) < total,
    }


@router.post("")
async def manual_import_assets(
    req: ManualAssetImportRequest,
    session: AsyncSession = Depends(get_session),
):
    raw_items = list(req.seeds or [])
    if req.seeds_text.strip():
        raw_items.append(req.seeds_text)
    parsed = svc.parse_seed_inputs(raw_items)
    if not any(parsed.values()):
        raise HTTPException(status_code=400, detail="请至少输入一个有效的域名、URL、IP 或网段")

    comp = await session.get(AssetCompany, req.company_id) if req.company_id else None
    companies = (await session.execute(select(AssetCompany))).scalars().all()
    totals = {k: 0 for k in svc.ASSET_TYPES}

    for u in parsed["urls"]:
        c = await svc.ingest_url_into_assets(
            session,
            url=u,
            source="manual",
            company_id=comp.id if comp else None,
            company_name=comp.name if comp else "",
            company_source="explicit" if comp else "scope",
            companies_cache=companies,
        )
        for k, v in c.items():
            totals[k] += v

    for d in parsed["domains"]:
        c = await svc.ingest_url_into_assets(
            session,
            host=d,
            source="manual",
            company_id=comp.id if comp else None,
            company_name=comp.name if comp else "",
            company_source="explicit" if comp else "scope",
            companies_cache=companies,
        )
        for k, v in c.items():
            totals[k] += v

    for ip in parsed["ips"]:
        c = await svc.ingest_url_into_assets(
            session,
            ip=ip,
            source="manual",
            company_id=comp.id if comp else None,
            company_name=comp.name if comp else "",
            company_source="explicit" if comp else "scope",
            companies_cache=companies,
        )
        for k, v in c.items():
            totals[k] += v

    await session.commit()
    return {"ok": True, "inserted": totals, "total_inserted": sum(totals.values())}


@router.post("/batch-delete")
async def batch_delete_assets(
    req: BatchDeleteAssetsRequest,
    session: AsyncSession = Depends(get_session),
):
    ids = [str(i).strip() for i in req.ids if str(i).strip()]
    if not ids or len(ids) > 500:
        raise HTTPException(status_code=400, detail="ids 数量必须为 1-500")
    res = await session.execute(delete(GlobalAsset).where(GlobalAsset.id.in_(ids)))
    await session.commit()
    return {"ok": True, "deleted": int(res.rowcount or 0)}


@router.post("/sync-from-tasks")
async def sync_from_tasks(
    req: SyncFromTasksRequest,
    session: AsyncSession = Depends(get_session),
):
    totals = await svc.sync_task_data_to_global_assets(session, task_id=req.task_id or None)
    await session.commit()
    return {"ok": True, "synced": totals}


# ── 企业/主体与范围归属管理 ───────────────────────────────────
@router.get("/companies")
async def list_companies(session: AsyncSession = Depends(get_session)):
    comps = (await session.execute(select(AssetCompany).order_by(desc(AssetCompany.updated_at)))).scalars().all()
    cnt_rows = (
        await session.execute(
            select(GlobalAsset.company_id, func.count())
            .where(GlobalAsset.company_id.is_not(None))
            .group_by(GlobalAsset.company_id)
        )
    ).all()
    cnt_map = {cid: int(cnt or 0) for cid, cnt in cnt_rows}
    return {"companies": [_company_dto(c, cnt_map.get(c.id, 0)) for c in comps]}


@router.post("/companies")
async def create_company(
    req: CompanyCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="企业/组织名称不能为空")
    nkey = svc.normalize_company_key(name)
    exists = (await session.execute(select(AssetCompany).where(AssetCompany.nkey == nkey))).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"主体「{name}」已存在")

    rules = svc.normalize_scope_rules([r.model_dump() for r in req.scope_rules])
    comp = AssetCompany(name=name[:200], nkey=nkey[:200], scope_rules=rules, notes=(req.notes or "").strip())
    session.add(comp)
    await session.flush()
    claimed = await svc.claim_assets_for_company(session, comp)
    await session.commit()
    await session.refresh(comp)
    return {"ok": True, "company": _company_dto(comp, claimed), "claimed_assets": claimed}


@router.patch("/companies/{company_id}")
async def update_company(
    company_id: str,
    req: CompanyPatchRequest,
    session: AsyncSession = Depends(get_session),
):
    comp = await session.get(AssetCompany, company_id)
    if not comp:
        raise HTTPException(status_code=404, detail="主体不存在")
    if req.name is not None:
        clean = req.name.strip()
        if not clean:
            raise HTTPException(status_code=400, detail="主体名称不能为空")
        comp.name = clean[:200]
        comp.nkey = svc.normalize_company_key(clean)[:200]
    if req.scope_rules is not None:
        comp.scope_rules = svc.normalize_scope_rules([r.model_dump() for r in req.scope_rules])
    if req.notes is not None:
        comp.notes = req.notes.strip()
    comp.updated_at = datetime.now(timezone.utc)
    claimed = await svc.claim_assets_for_company(session, comp)
    await session.commit()
    await session.refresh(comp)
    return {"ok": True, "company": _company_dto(comp), "claimed_assets": claimed}


@router.delete("/companies/{company_id}")
async def delete_company(
    company_id: str,
    delete_assets: bool = Query(False),
    session: AsyncSession = Depends(get_session),
):
    comp = await session.get(AssetCompany, company_id)
    if not comp:
        raise HTTPException(status_code=404, detail="主体不存在")
    if delete_assets:
        await session.execute(delete(GlobalAsset).where(GlobalAsset.company_id == company_id))
    else:
        await session.execute(
            update(GlobalAsset)
            .where(GlobalAsset.company_id == company_id)
            .values(company_id=None, company_name="", company_source="scope")
        )
    await session.delete(comp)
    await session.commit()
    return {"ok": True, "deleted": company_id}


# ── 双图拓扑与血缘追踪 ────────────────────────────────────────
@router.get("/dual-graph")
async def get_dual_graph(
    task_id: str | None = Query(None),
    company_id: str | None = Query(None),
    limit: int = Query(240, ge=20, le=500),
    session: AsyncSession = Depends(get_session),
):
    return await svc.build_dual_graph(
        session,
        task_id=(task_id or "").strip() or None,
        company_id=(company_id or "").strip() or None,
        limit=limit,
    )


@router.get("/dual-graph/lineage")
async def get_dual_graph_lineage(
    node_id: str = Query(...),
    task_id: str | None = Query(None),
    company_id: str | None = Query(None),
    direction: str = Query("both", pattern="^(backward|forward|both)$"),
    session: AsyncSession = Depends(get_session),
):
    graph = await svc.build_dual_graph(
        session,
        task_id=(task_id or "").strip() or None,
        company_id=(company_id or "").strip() or None,
    )
    chain = fusion_graphs.lineage(graph["nodes"], graph["edges"], node_id, max_depth=8, direction=direction)
    return {"node_id": node_id, "direction": direction, "lineage": chain}


# ── 资产一键转为挖掘任务 ──────────────────────────────────────
@router.post("/to-task")
async def create_task_from_assets(
    req: AssetsToTaskRequest,
    session: AsyncSession = Depends(get_session),
):
    await refresh_cache(session)
    stmt = select(GlobalAsset)
    if req.asset_ids:
        stmt = stmt.where(GlobalAsset.id.in_(req.asset_ids))
    elif req.company_id:
        stmt = stmt.where(
            GlobalAsset.company_id == req.company_id,
            GlobalAsset.asset_type.in_(("service", "subdomain", "endpoint", "ip")),
        )
    else:
        raise HTTPException(status_code=400, detail="请勾选至少一条资产或指定归属主体")

    rows = (await session.execute(stmt.order_by(desc(GlobalAsset.last_seen)).limit(300))).scalars().all()
    if not rows:
        raise HTTPException(status_code=400, detail="未找到可转换为目标的有效资产")

    manual_targets: list[str] = []
    seen: set[str] = set()
    for a in rows:
        candidate = ""
        if a.asset_type in ("service", "endpoint") and a.value.startswith(("http://", "https://")):
            candidate = a.value
        elif a.host:
            candidate = f"https://{a.host}" if a.port == 443 else f"http://{a.host}"
        elif a.ip:
            candidate = f"http://{a.ip}"
        if candidate and candidate not in seen:
            seen.add(candidate)
            manual_targets.append(candidate)

    if not manual_targets:
        raise HTTPException(status_code=400, detail="所选资产无法构造有效 URL 目标")

    eff = effective_settings()
    task_name = (req.name or "").strip() or f"[资产库] 自动化挖掘 ({len(manual_targets)} 目标)"
    src_type = normalize_src_type(req.src_type or "edusrc")
    guard_ops = (
        normalize_guard_ops(req.guard_ops)
        if req.guard_ops is not None
        else ["db_dump", "db_delete", "dos", "webshell"]
    )
    concurrency = _clamp_task_concurrency(
        req.concurrency,
        default=_clamp_task_concurrency((eff.get("defaults") or {}).get("concurrency"), default=3),
    )
    deepen_cap = clamp_deepen_cap((eff.get("defaults") or {}).get("deepen_cap"))

    new_task = Task(
        name=task_name[:200],
        src_type=src_type,
        vuln_types=[],
        src_rules=f"由全局双图资产库一键发起，共导入 {len(manual_targets)} 个经收集验证的目标。",
        guard_ops=guard_ops,
        target_source="manual",
        engine="",
        fofa_query="",
        manual_targets=manual_targets,
        auth_bindings=[],
        model_config_json={"inherit_global": True},
        fofa_config={"source": "global_assets", "asset_count": len(manual_targets)},
        concurrency=concurrency,
        deepen_cap=deepen_cap,
        status="running" if req.start_immediately else "created",
    )
    session.add(new_task)
    await session.flush()
    session.add(
        TaskEvent(
            task_id=new_task.id,
            agent="assets",
            level="info",
            kind="assets_task_created",
            message=f"已从全局双图资产库导入 {len(manual_targets)} 个目标创建挖掘任务",
            payload={"count": len(manual_targets), "start_immediately": bool(req.start_immediately)},
        )
    )
    await session.commit()
    await session.refresh(new_task)

    if req.start_immediately:
        await manager.ensure_running(new_task.id)

    return {
        "ok": True,
        "started": bool(req.start_immediately),
        "target_count": len(manual_targets),
        "task": _task_to_dto(new_task).model_dump(),
    }


# ── 自动化资产收集任务 API ────────────────────────────────────
@router.post("/collect/jobs")
async def start_collect_job(
    req: CollectJobCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    await refresh_cache(session)
    seeds_list = [s.strip() for s in (req.seeds or []) if s and s.strip()]
    if req.seeds_text.strip():
        seeds_list.extend([s.strip() for s in req.seeds_text.replace(",", "\n").splitlines() if s.strip()])

    valid_sources = [s for s in (req.sources or []) if s in {"crtsh", "dns", "http_probe", "engine", "task_sync"}]
    if not valid_sources:
        valid_sources = ["crtsh", "dns", "http_probe"]

    engine_name = (req.engine or "").strip().lower()
    if "engine" in valid_sources:
        if not engine_name:
            engine_name = str((effective_settings().get("defaults") or {}).get("engine") or "fofa")
        eng = get_engine(engine_name)
        if eng is None:
            raise HTTPException(status_code=400, detail=f"不支持的测绘引擎：{engine_name}")
        if not resolve_engine_key(engine_name):
            raise HTTPException(
                status_code=400,
                detail=f"测绘引擎 {eng.display_name} 尚未配置 API Key，请取消勾选测绘源或先前往系统设置配置",
            )

    if not seeds_list and not req.engine_query.strip() and "task_sync" not in valid_sources:
        raise HTTPException(status_code=400, detail="请输入至少一个根域名、URL、IP/网段种子，或填写测绘查询语法")

    comp = await session.get(AssetCompany, req.company_id) if req.company_id else None
    default_name = f"自动收集 · {seeds_list[0][:36]}" if seeds_list else (
        f"测绘收集 · {req.engine_query[:36]}" if req.engine_query.strip() else "全量任务资产同步收集"
    )
    job = AssetCollectJob(
        name=(req.name or "").strip()[:200] or default_name,
        mode="manual",
        prompt="",
        seeds=seeds_list[:100],
        company_id=comp.id if comp else None,
        company_name=comp.name if comp else "",
        sources=valid_sources,
        engine=engine_name,
        engine_query=(req.engine_query or "").strip(),
        max_pages=int(req.max_pages),
        status="running",
        stats={},
        logs=[{"ts": to_cst_iso(datetime.now(timezone.utc)), "message": "资产自动收集任务已创建，正在初始化采集源…"}],
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    svc.launch_collect_job_background(job.id)
    return {"ok": True, "job": _job_dto(job)}


@router.post("/collect/ai-plan")
async def preview_ai_collect_plan(
    req: AICollectPlanRequest,
    session: AsyncSession = Depends(get_session),
):
    """自然语言资产收集预规划：调用 AI 解析目标边界、归属主体、测绘语法与执行步骤。"""
    await refresh_cache(session)
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="请输入自然语言资产收集需求")
    if not resolve_llm_providers(None):
        raise HTTPException(
            status_code=503,
            detail="尚未配置大模型 API Key，请先前往「模型与多角色路由」或「系统设置」完成配置",
        )
    try:
        plan = await ai_collector.plan_collection_from_prompt(
            prompt, session, preferred_engine=(req.preferred_engine or "").strip().lower()
        )
        return {"ok": True, "plan": plan}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 收集规划失败：{exc}") from exc


@router.post("/collect/ai-jobs")
async def start_ai_collect_job(
    req: AICollectJobCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    """基于自然语言启动 AI 自主资产收集 Agent，自主思考并多轮调用真实探测/测绘工具。"""
    await refresh_cache(session)
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="请用自然语言描述需要收集的目标资产与要求")
    if not resolve_llm_providers(None):
        raise HTTPException(
            status_code=503,
            detail="尚未配置大模型 API Key，请先前往「模型与多角色路由」或「系统设置」完成配置",
        )

    comp = await session.get(AssetCompany, req.company_id) if req.company_id else None
    pref_eng = (req.preferred_engine or "").strip().lower()
    if pref_eng and get_engine(pref_eng) is None:
        raise HTTPException(status_code=400, detail=f"不支持的测绘引擎：{pref_eng}")

    auto_title = (req.name or "").strip()[:200] or f"AI 收集 · {prompt.splitlines()[0][:36]}"
    job = AssetCollectJob(
        name=auto_title,
        mode="ai",
        prompt=prompt,
        seeds=[],
        company_id=comp.id if comp else None,
        company_name=comp.name if comp else "",
        sources=["ai_agent"],
        engine=pref_eng,
        engine_query="",
        max_pages=3,
        status="running",
        stats={},
        logs=[{"ts": to_cst_iso(datetime.now(timezone.utc)), "message": "AI 自主资产收集任务已启动，正在调用大模型思考规划…"}],
        ai_plan={},
        ai_trace=[{
            "ts": to_cst_iso(datetime.now(timezone.utc)),
            "kind": "thinking",
            "title": "已接收自然语言收集指令",
            "detail": prompt,
            "tool_name": "",
            "duration_ms": 0,
        }],
        ai_summary="",
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    ai_collector.launch_ai_collect_job_background(
        job.id,
        max_rounds=int(req.max_rounds),
        preferred_engine=pref_eng,
    )
    return {"ok": True, "job": _job_dto(job)}


@router.get("/collect/jobs")
async def list_collect_jobs(
    limit: int = Query(30, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(select(AssetCollectJob).order_by(desc(AssetCollectJob.created_at)).limit(limit))
    ).scalars().all()
    return {"jobs": [_job_dto(j) for j in rows]}


@router.get("/collect/jobs/{job_id}")
async def get_collect_job(
    job_id: str,
    session: AsyncSession = Depends(get_session),
):
    job = await session.get(AssetCollectJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="收集任务不存在")
    return _job_dto(job)


@router.post("/collect/jobs/{job_id}/stop")
async def stop_collect_job(
    job_id: str,
    session: AsyncSession = Depends(get_session),
):
    job = await session.get(AssetCollectJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="收集任务不存在")
    stopped = svc.cancel_collect_job(job_id)
    return {"ok": True, "status": "stopping" if stopped else job.status}
