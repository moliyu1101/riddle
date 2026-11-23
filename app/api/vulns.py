"""全局漏洞库 API：跨任务聚合「人工审核通过」的漏洞。

收录范围（用户复审通过 user_status == "passed"）：
- 已提交 SRC：Review.submitted == True
- 未提交但过审：Review.submitted == False（即待提交）
排除 Finding.status == "superseded"（深挖让位项，不算正式漏洞）。

该接口含 PoC/证据等敏感数据，鉴权同 /api/intel：full/readonly 可看，
observer 不在白名单（middleware 直接 403）。分页结构与硬骨头库一致。
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.deepen import clamp_deepen_cap
from app.agents.prompts import normalize_src_type
from app.api.tasks import _clamp_task_concurrency, _task_to_dto
from app.db.models import Finding, Killsweep, Review, Task, TaskEvent, to_cst_iso
from app.db.session import get_session
from app.engines import get_engine, list_engines
from app.orchestrator import manager
from app.settings_service import (
    effective_settings,
    public_settings_view,
    refresh_cache,
    resolve_engine_key,
)
from app.tools.guard import normalize_guard_ops

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


def _base_conds():
    """全局漏洞库基础筛选：人工审核通过、非 superseded。"""
    return [
        Review.user_status == "passed",
        Finding.status != "superseded",
    ]


def _vuln_dict(f: Finding, r: Review, task_name: str = "") -> dict:
    user_edits = r.user_edits or {}
    title = user_edits.get("title") or f.title
    return {
        "id": f.id,
        "task_id": f.task_id,
        "task_name": task_name or "",
        "target_id": f.target_id,
        "vuln_type": f.vuln_type,
        "title": title,
        "target_url": f.target_url,
        "owner": f.owner,
        "severity_claimed": f.severity_claimed,
        "kill_chain": [
            {"method": str(s.get("method") or ""), "detail": str(s.get("detail") or "")}
            for s in (f.kill_chain or [])
            if isinstance(s, dict) and s.get("method")
        ],
        "created_at": to_cst_iso(f.created_at),
        "llm_model": getattr(f, "llm_model", "") or "",
        "llm_base_url": getattr(f, "llm_base_url", "") or "",
        "confidence": r.confidence,
        "score": r.score,
        "effective_severity": r.user_severity or r.severity_final,
        "submitted": r.submitted,
        "user_reviewed_at": to_cst_iso(r.user_reviewed_at),
    }


@router.get("/stats")
async def vuln_stats(session: AsyncSession = Depends(get_session)):
    """全局漏洞库总览：总数、已提交、待提交、各等级分布。"""
    conds = _base_conds()
    total = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds))
    )).scalar() or 0
    submitted = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds, Review.submitted.is_(True)))
    )).scalar() or 0
    by_sev: dict[str, int] = {}
    sev_expr = func.coalesce(Review.user_severity, Review.severity_final)
    rows = await session.execute(
        select(sev_expr, func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(and_(*conds))
        .group_by(sev_expr)
    )
    for sev, cnt in rows.all():
        by_sev[sev or "未定级"] = cnt
    return {
        "total": total,
        "submitted": submitted,
        "ready": total - submitted,
        "by_severity": by_sev,
    }


@router.get("")
async def list_vulns(
    submitted: str = Query("all", pattern="^(all|yes|no)$"),
    severity: Optional[str] = Query(None),
    q: str | None = Query(None),
    sort: str = Query("time_desc", pattern="^(time_desc|time_asc|score_desc|score_asc)$"),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """分页列出全局漏洞库。submitted: all/yes(已提交)/no(待提交)。

    sort: time_desc(按时间最新)/time_asc(按时间最旧)/score_desc(评分最高)/score_asc(评分最低)。
    """
    safe_limit = max(1, min(int(limit or 100), 200))
    safe_offset = max(0, int(offset or 0))
    conds = _base_conds()
    if submitted == "yes":
        conds.append(Review.submitted.is_(True))
    elif submitted == "no":
        conds.append(Review.submitted.is_(False))
    if severity:
        conds.append(func.coalesce(Review.user_severity, Review.severity_final) == severity)
    needle = (q or "").strip()
    if needle:
        like = f"%{needle}%"
        conds.append(or_(
            Finding.title.ilike(like),
            Finding.vuln_type.ilike(like),
            Finding.target_url.ilike(like),
            Finding.owner.ilike(like),
            Task.name.ilike(like),
        ))

    total = (await session.execute(
        select(func.count())
        .select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(and_(*conds))
    )).scalar() or 0

    # 时间排序键：优先审核时间，无则回退发现时间
    time_expr = func.coalesce(Review.user_reviewed_at, Finding.created_at)
    if sort == "time_asc":
        order = (time_expr.asc(),)
    elif sort == "score_desc":
        order = (Review.score.desc(), time_expr.desc())
    elif sort == "score_asc":
        order = (Review.score.asc(), time_expr.desc())
    else:
        order = (time_expr.desc(),)

    stmt = (
        select(Finding, Review, Task.name)
        .join(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(and_(*conds))
        .order_by(*order)
        .offset(safe_offset)
        .limit(safe_limit)
    )
    rows = (await session.execute(stmt)).all()
    out = [_vuln_dict(f, r, task_name) for f, r, task_name in rows]
    return {
        "items": out,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "has_more": safe_offset + len(out) < total,
    }


_DEFAULT_KILLSWEEP_GUARD_OPS = ["db_dump", "db_delete", "dos", "webshell"]


class KillsweepTaskCreateRequest(BaseModel):
    engine: str = ""
    query: str = ""
    name: str = ""
    src_type: str = ""
    concurrency: int | None = None
    deepen_cap: int | None = None
    max_pages: int = Field(default=20, ge=1, le=200)
    page_size: int = Field(default=100, ge=10, le=500)
    extra_src_rules: str = ""
    guard_ops: list[str] | None = None
    start_immediately: bool = True


def _escape_query_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').strip()


def _extract_title_keyword(title: str) -> str:
    cleaned = re.sub(r"[\[\]【】()（）]", " ", title or "").strip()
    cleaned = re.sub(r"^(存在|发现|某高校|高校|疑似)\s*", "", cleaned).strip()
    for sep in ("存在", "漏洞", "未授权", "注入", "越权", "接管", "泄露", "弱口令", "任意文件", "命令执行", " - ", "—", "：", ":"):
        idx = cleaned.find(sep)
        if idx >= 2:
            cleaned = cleaned[:idx].strip()
            break
    return cleaned[:40].strip()


def _suggest_killsweep_query(
    finding: Finding,
    ks: Killsweep | None,
    src_type: str,
) -> tuple[str, str]:
    """生成通杀测绘初始语法，优先复用历史 Killsweep 记录中的语法。"""
    if ks and (ks.fofa_query or "").strip():
        return ks.fofa_query.strip(), "killsweep"

    expr = ""
    if ks and (ks.product_name or "").strip():
        expr = f'title="{_escape_query_literal(ks.product_name.strip())}"'
    else:
        parsed = urlparse((finding.target_url or "").strip())
        path = (parsed.path or "").strip()
        segments = [seg for seg in path.split("/") if seg and len(seg) >= 3]
        if segments and segments[0].lower() not in {"index.html", "index.php", "index.jsp", "login", "api", "admin"}:
            expr = f'body="{_escape_query_literal("/" + segments[0])}"'
        else:
            kw = _extract_title_keyword(finding.title or "")
            if kw:
                expr = f'title="{_escape_query_literal(kw)}"'

    if not expr:
        expr = 'title="管理系统"'

    if src_type == "edusrc" and "edu.cn" not in expr.lower():
        expr = f'{expr} && domain="edu.cn"'
    return expr, "suggested"


def _suggest_task_name(finding: Finding, review: Review | None, ks: Killsweep | None) -> str:
    user_edits = (review.user_edits or {}) if review else {}
    effective_title = str(user_edits.get("title") or finding.title or "").strip()
    label = (ks.product_name.strip() if ks and ks.product_name else "") or effective_title or finding.vuln_type or finding.id
    return f"[通杀] {label[:48]}"


def _build_killsweep_src_rules(
    finding: Finding,
    review: Review | None,
    origin_task: Task | None,
    ks: Killsweep | None,
    extra_rules: str = "",
) -> str:
    parts: list[str] = []
    if origin_task and (origin_task.src_rules or "").strip():
        parts.append(origin_task.src_rules.strip())

    user_edits = (review.user_edits or {}) if review else {}
    effective_title = str(user_edits.get("title") or finding.title or "").strip()
    effective_poc = str(user_edits.get("poc") or finding.poc or "").strip()
    effective_desc = str(user_edits.get("description") or finding.description or "").strip()

    ctx_lines = [
        "【漏洞库一键通杀上下文】",
        f"- 源漏洞 ID: {finding.id}",
        f"- 漏洞标题: {effective_title}",
        f"- 漏洞类型: {finding.vuln_type or '未知'}",
        f"- 参考样本 URL: {finding.target_url}",
    ]
    if ks:
        if ks.product_name:
            ctx_lines.append(f"- 识别产品/组件: {ks.product_name}")
        if ks.fingerprint:
            ctx_lines.append(f"- 指纹特征: {ks.fingerprint[:300]}")
        if ks.vuln_summary:
            ctx_lines.append(f"- 通杀说明: {ks.vuln_summary[:400]}")
    if effective_desc:
        ctx_lines.append(f"- 漏洞摘要: {effective_desc[:400]}")
    if effective_poc:
        ctx_lines.append(f"- 参考验证方式 (仅在授权范围内做无害验证):\n{effective_poc[:800]}")
    parts.append("\n".join(ctx_lines))

    if (extra_rules or "").strip():
        parts.append(extra_rules.strip())

    return "\n\n".join(parts)


async def _load_finding_killsweep_context(
    session: AsyncSession,
    finding_id: str,
) -> tuple[Finding, Review | None, Task | None, Killsweep | None]:
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="未找到对应漏洞记录")

    review = (
        await session.execute(select(Review).where(Review.finding_id == finding.id))
    ).scalar_one_or_none()
    origin_task = await session.get(Task, finding.task_id) if finding.task_id else None
    ks = (
        await session.execute(
            select(Killsweep)
            .where(Killsweep.origin_finding_id == finding.id)
            .order_by(Killsweep.updated_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return finding, review, origin_task, ks


@router.get("/{finding_id}/killsweep-preview")
async def killsweep_preview(
    finding_id: str,
    session: AsyncSession = Depends(get_session),
):
    """预览已落盘漏洞的一键通杀任务参数与测绘引擎配置状态。"""
    await refresh_cache(session)
    finding, review, origin_task, ks = await _load_finding_killsweep_context(session, finding_id)

    pub = public_settings_view()
    eff = effective_settings()
    engines_pub = pub.get("engines") or {}
    engines_list = []
    configured_names: list[str] = []
    for eng in list_engines():
        name = eng["name"]
        info = engines_pub.get(name) or {}
        key_set = bool(info.get("key_set"))
        if key_set:
            configured_names.append(name)
        engines_list.append({
            "name": name,
            "display_name": eng["display_name"],
            "key_set": key_set,
            "base_url": info.get("base_url") or "",
        })

    preferred_engine = (
        (origin_task.engine if origin_task and origin_task.engine else "")
        or str((eff.get("defaults") or {}).get("engine") or "fofa")
    ).strip().lower()
    if get_engine(preferred_engine) is None:
        preferred_engine = "fofa"

    preferred_configured = any(e["name"] == preferred_engine and e["key_set"] for e in engines_list)
    default_engine = preferred_engine if preferred_configured else (configured_names[0] if configured_names else preferred_engine)

    default_src_type = normalize_src_type(origin_task.src_type if origin_task else "edusrc")
    suggested_query, query_source = _suggest_killsweep_query(finding, ks, default_src_type)
    suggested_name = _suggest_task_name(finding, review, ks)
    default_guard_ops = (
        normalize_guard_ops(origin_task.guard_ops)
        if origin_task and origin_task.guard_ops
        else list(_DEFAULT_KILLSWEEP_GUARD_OPS)
    )

    user_edits = (review.user_edits or {}) if review else {}
    effective_title = str(user_edits.get("title") or finding.title or "")
    effective_severity = (
        (review.user_severity or review.severity_final) if review else None
    ) or finding.severity_claimed or "中危"

    return {
        "finding": {
            "id": finding.id,
            "task_id": finding.task_id or "",
            "task_name": origin_task.name if origin_task else "",
            "title": effective_title,
            "vuln_type": finding.vuln_type,
            "target_url": finding.target_url,
            "owner": finding.owner,
            "effective_severity": effective_severity,
            "user_status": review.user_status if review else "",
        },
        "killsweep": {
            "id": ks.id,
            "product_name": ks.product_name,
            "fingerprint": ks.fingerprint,
            "fofa_query": ks.fofa_query,
            "vuln_summary": ks.vuln_summary,
            "asset_count": ks.asset_count,
            "edu_count": ks.edu_count,
            "verified": ks.verified,
        } if ks else None,
        "suggested_name": suggested_name,
        "suggested_query": suggested_query,
        "query_source": query_source,
        "default_src_type": default_src_type,
        "default_engine": default_engine,
        "has_configured_engine": bool(configured_names),
        "engines": engines_list,
        "defaults": {
            "concurrency": _clamp_task_concurrency((eff.get("defaults") or {}).get("concurrency"), default=3),
            "deepen_cap": clamp_deepen_cap((eff.get("defaults") or {}).get("deepen_cap")),
            "max_pages": int((eff.get("fofa") or {}).get("max_pages") or 20),
            "page_size": int((eff.get("fofa") or {}).get("page_size") or 100),
            "guard_ops": default_guard_ops,
        },
    }


@router.post("/{finding_id}/killsweep-task")
async def create_killsweep_task(
    finding_id: str,
    req: KillsweepTaskCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    """基于已落盘漏洞一键落盘为新的通杀测绘任务，并按配置立即启动。"""
    await refresh_cache(session)
    finding, review, origin_task, ks = await _load_finding_killsweep_context(session, finding_id)
    eff = effective_settings()

    engine_name = (
        req.engine
        or (origin_task.engine if origin_task and origin_task.engine else "")
        or str((eff.get("defaults") or {}).get("engine") or "fofa")
    ).strip().lower()
    engine_cls = get_engine(engine_name)
    if engine_cls is None:
        raise HTTPException(status_code=400, detail=f"不支持的测绘引擎：{engine_name}")

    engine_key = resolve_engine_key(engine_name)
    if not engine_key:
        raise HTTPException(
            status_code=400,
            detail=f"测绘引擎 {engine_cls.display_name} 尚未配置 API Key，请先前往「系统设置」完成配置后再发起通杀",
        )

    src_type = normalize_src_type(req.src_type or (origin_task.src_type if origin_task else "edusrc"))
    query = (req.query or "").strip() or (ks.fofa_query.strip() if ks and ks.fofa_query else "")
    if not query:
        raise HTTPException(status_code=400, detail="请填写测绘查询语法后再创建通杀任务")

    task_name = (req.name or "").strip() or _suggest_task_name(finding, review, ks)
    guard_ops = (
        normalize_guard_ops(req.guard_ops)
        if req.guard_ops is not None
        else (
            normalize_guard_ops(origin_task.guard_ops)
            if origin_task and origin_task.guard_ops
            else list(_DEFAULT_KILLSWEEP_GUARD_OPS)
        )
    )
    concurrency = _clamp_task_concurrency(
        req.concurrency,
        default=_clamp_task_concurrency((eff.get("defaults") or {}).get("concurrency"), default=3),
    )
    deepen_cap = clamp_deepen_cap(
        req.deepen_cap if req.deepen_cap is not None else (eff.get("defaults") or {}).get("deepen_cap")
    )
    src_rules = _build_killsweep_src_rules(finding, review, origin_task, ks, req.extra_src_rules)
    vuln_types = [finding.vuln_type] if (finding.vuln_type or "").strip() else []

    new_task = Task(
        name=task_name,
        src_type=src_type,
        vuln_types=vuln_types,
        src_rules=src_rules,
        guard_ops=guard_ops,
        target_source="fofa",
        engine=engine_name,
        fofa_query=query,
        manual_targets=[],
        auth_bindings=[],
        model_config_json={"inherit_global": True},
        fofa_config={
            "max_pages": int(req.max_pages),
            "page_size": int(req.page_size),
            "origin_finding_id": finding.id,
            "origin_task_id": finding.task_id or "",
            "killsweep_mode": True,
        },
        concurrency=concurrency,
        deepen_cap=deepen_cap,
        status="running" if req.start_immediately else "created",
    )
    session.add(new_task)
    await session.flush()

    session.add(
        TaskEvent(
            task_id=new_task.id,
            agent="killsweep",
            level="info",
            kind="killsweep_task_created",
            message=(
                f"已由漏洞「{finding.title[:60]}」一键落盘为通杀任务"
                f"（引擎：{engine_cls.display_name}，语法：{query[:120]}）"
            ),
            payload={
                "origin_finding_id": finding.id,
                "origin_task_id": finding.task_id or "",
                "engine": engine_name,
                "query": query,
                "start_immediately": bool(req.start_immediately),
            },
        )
    )
    await session.commit()
    await session.refresh(new_task)

    if req.start_immediately:
        await manager.ensure_running(new_task.id)

    return {
        "ok": True,
        "started": bool(req.start_immediately),
        "task": _task_to_dto(new_task).model_dump(),
    }
