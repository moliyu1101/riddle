"""全局情报库 API：列表 / 统计 / 删除。

情报库是跨任务共享的可复用知识沉淀（cred/fingerprint/endpoint/profile）。
提供给前端「情报库控制台」浏览、筛选、清理。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.intel_curator import curate_intel
from app.db.models import Intel, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/intel", tags=["intel"])

_KINDS = ("cred", "fingerprint", "endpoint", "profile", "lesson")


def _intel_to_dict(it: Intel) -> dict:
    return {
        "id": it.id,
        "kind": it.kind,
        "match_key": it.match_key,
        "payload": it.payload or {},
        "summary": it.summary or "",
        "source_host": it.source_host or "",
        "source_task_id": it.source_task_id or "",
        "confidence": it.confidence or "likely",
        "hit_count": it.hit_count or 1,
        "first_seen": to_cst_iso(it.first_seen),
        "last_seen": to_cst_iso(it.last_seen),
    }


@router.get("/stats")
async def intel_stats(session: AsyncSession = Depends(get_session)):
    """情报库总览：总条数、各类别数、已验证数、被复用(hit>1)数。"""
    total = (await session.execute(select(func.count()).select_from(Intel))).scalar() or 0
    by_kind = {}
    rows = await session.execute(select(Intel.kind, func.count()).group_by(Intel.kind))
    for kind, cnt in rows.all():
        by_kind[kind] = cnt
    verified = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.confidence == "verified")
    )).scalar() or 0
    reused = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.hit_count > 1)
    )).scalar() or 0
    return {
        "total": total,
        "by_kind": {k: by_kind.get(k, 0) for k in _KINDS},
        "verified": verified,
        "reused": reused,
    }


@router.get("/hit-stats")
async def intel_hit_stats(session: AsyncSession = Depends(get_session)):
    """情报命中统计面板：各类别复用概况 + 复用分布 + 高频复用 Top + 来源主机 Top。

    用于前端「命中统计」区块，回答三个问题：
    - 哪类情报被复用最多（by_kind.avg_hit / reused）；
    - 复用次数分布（once 一次未复用 / few 2-5 次 / many 6+ 次）；
    - 哪些情报 / 哪些来源主机贡献最大（top_reused / top_sources）。
    """
    rows = (await session.execute(
        select(Intel.kind, Intel.confidence, Intel.hit_count, Intel.source_host)
    )).all()
    top_reused = (await session.execute(
        select(Intel).where(Intel.hit_count > 1)
        .order_by(Intel.hit_count.desc(), Intel.last_seen.desc()).limit(10)
    )).scalars().all()
    return _aggregate_hit_stats(rows, top_reused)


def _aggregate_hit_stats(rows, top_reused):
    """纯函数：把 (kind, confidence, hit_count, source_host) 行聚合成命中统计字典（可单测）。"""
    by_kind: dict[str, dict] = {k: {"total": 0, "verified": 0, "reused": 0, "avg_hit": 0.0} for k in _KINDS}
    dist = {"once": 0, "few": 0, "many": 0}
    src_counter: dict[str, int] = {}
    for kind, conf, hit, host in rows:
        k = kind if kind in by_kind else "other"
        if k not in by_kind:
            by_kind[k] = {"total": 0, "verified": 0, "reused": 0, "avg_hit": 0.0}
        b = by_kind[k]
        b["total"] += 1
        if conf == "verified":
            b["verified"] += 1
        if (hit or 1) > 1:
            b["reused"] += 1
        b["avg_hit"] += hit or 1
        if (hit or 1) == 1:
            dist["once"] += 1
        elif (hit or 1) <= 5:
            dist["few"] += 1
        else:
            dist["many"] += 1
        if host:
            src_counter[host] = src_counter.get(host, 0) + 1
    for b in by_kind.values():
        b["avg_hit"] = round(b["avg_hit"] / b["total"], 2) if b["total"] else 0.0

    top_sources = sorted(src_counter.items(), key=lambda x: x[1], reverse=True)[:8]
    return {
        "by_kind": by_kind,
        "reuse_dist": dist,
        "top_reused": [
            {"id": it.id, "kind": it.kind, "match_key": it.match_key,
             "summary": it.summary or "", "hit_count": it.hit_count or 1,
             "last_seen": to_cst_iso(it.last_seen)}
            for it in top_reused
        ],
        "top_sources": [{"host": h, "count": c} for h, c in top_sources],
    }


@router.get("")
async def list_intel(
    kind: str = Query("all"),
    confidence: str = Query("all", pattern="^(all|verified|likely)$"),
    q: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """情报列表：按类别/可信度筛选 + 关键词搜索（match_key/summary/source_host/payload）。"""
    stmt = select(Intel)
    if kind in _KINDS:
        stmt = stmt.where(Intel.kind == kind)
    if confidence in ("verified", "likely"):
        stmt = stmt.where(Intel.confidence == confidence)
    stmt = stmt.order_by(
        Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc()
    ).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()
    out = [_intel_to_dict(it) for it in rows]
    # 关键词在内存过滤（覆盖 match_key/summary/source_host/payload 全字段；
    # SQLite JSON 列检索能力有限，统一在内存做更可靠，数据量小性能无忧）。
    needle = (q or "").strip().lower()
    if needle:
        out = [
            d for d in out
            if (needle in (d["match_key"] or "").lower()
                or needle in (d["summary"] or "").lower()
                or needle in (d["source_host"] or "").lower()
                or needle in str(d["payload"]).lower())
        ]
    return out


@router.get("/curate")
async def preview_curate_intel(
    limit: int = Query(1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """预览 Intel Curator 将清理的低价值情报（不删除）。"""
    return await curate_intel(session, apply=False, limit=limit)


@router.post("/curate")
async def apply_curate_intel(
    limit: int = Query(1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
):
    """执行 Intel Curator 清理。仅 full 令牌可调用（中间件禁止 readonly/observer 写操作）。"""
    return await curate_intel(session, apply=True, limit=limit)


@router.delete("/{intel_id}")
async def delete_intel(intel_id: str, session: AsyncSession = Depends(get_session)):
    """删除一条情报（清理失效/误存的脏数据）。"""
    it = await session.get(Intel, intel_id)
    if not it:
        raise HTTPException(404, "情报不存在")
    await session.delete(it)
    await session.commit()
    return {"ok": True}


@router.delete("")
async def clear_intel(
    kind: str = Query("all"),
    session: AsyncSession = Depends(get_session),
):
    """批量清空（按类别或全部）。谨慎使用。"""
    stmt = select(Intel)
    if kind in _KINDS:
        stmt = stmt.where(Intel.kind == kind)
    rows = (await session.execute(stmt)).scalars().all()
    n = 0
    for it in rows:
        await session.delete(it)
        n += 1
    await session.commit()
    return {"ok": True, "deleted": n}
