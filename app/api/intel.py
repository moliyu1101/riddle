"""全局情报库 API：列表 / 统计 / 删除。

情报库是跨任务共享的可复用知识沉淀（cred/fingerprint/endpoint/profile）。
提供给前端「情报库控制台」浏览、筛选、清理。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.intel_curator import curate_intel
from app.agents.knowledge import sync_kb_from_files
from app.db.models import Intel, to_cst_iso
from app.db.session import get_session

router = APIRouter(prefix="/api/intel", tags=["intel"])

# 知识库（knowledge）是独立模块，有专属接口（/knowledge）与前端页签，不应混入"情报沉淀"的统计与列表。
_INTEL_KINDS = ("cred", "fingerprint", "endpoint", "profile", "lesson")
_KINDS = _INTEL_KINDS + ("knowledge",)


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
    """情报库总览：总条数、各类别数、已验证数、被复用(hit>1)数。

    仅统计真正的情报（cred/fingerprint/endpoint/profile/lesson），
    知识库（knowledge）走独立知识库接口，不计入这里。
    """
    total = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.kind != "knowledge")
    )).scalar() or 0
    by_kind = {}
    rows = await session.execute(
        select(Intel.kind, func.count()).where(Intel.kind.in_(_INTEL_KINDS)).group_by(Intel.kind)
    )
    for kind, cnt in rows.all():
        by_kind[kind] = cnt
    verified = (await session.execute(
        select(func.count()).select_from(Intel)
        .where(Intel.kind != "knowledge", Intel.confidence == "verified")
    )).scalar() or 0
    reused = (await session.execute(
        select(func.count()).select_from(Intel)
        .where(Intel.kind != "knowledge", Intel.hit_count > 1)
    )).scalar() or 0
    return {
        "total": total,
        "by_kind": {k: by_kind.get(k, 0) for k in _INTEL_KINDS},
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
        .where(Intel.kind != "knowledge")
    )).all()
    top_reused = (await session.execute(
        select(Intel).where(Intel.kind != "knowledge", Intel.hit_count > 1)
        .order_by(Intel.hit_count.desc(), Intel.last_seen.desc()).limit(10)
    )).scalars().all()
    return _aggregate_hit_stats(rows, top_reused)


def _aggregate_hit_stats(rows, top_reused):
    """纯函数：把 (kind, confidence, hit_count, source_host) 行聚合成命中统计字典（可单测）。"""
    by_kind: dict[str, dict] = {k: {"total": 0, "verified": 0, "reused": 0, "avg_hit": 0.0} for k in _INTEL_KINDS}
    dist = {"once": 0, "few": 0, "many": 0}
    src_counter: dict[str, int] = {}
    for kind, conf, hit, host in rows:
        if kind == "knowledge":
            # 知识库独立统计与展示，不进情报命中统计。
            continue
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
    if kind == "all":
        # 默认只列真正的情报；知识库用独立 /knowledge 接口 + 专属页签，不混入列表。
        stmt = stmt.where(Intel.kind.in_(_INTEL_KINDS))
    elif kind in _INTEL_KINDS:
        stmt = stmt.where(Intel.kind == kind)
    else:
        return []
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
    """批量清空（按类别或全部）。谨慎使用。默认 only 情报，知识库须显式 kind=knowledge 才会被清。"""
    stmt = select(Intel)
    if kind == "all":
        stmt = stmt.where(Intel.kind.in_(_INTEL_KINDS))
    elif kind in _INTEL_KINDS:
        stmt = stmt.where(Intel.kind == kind)
    elif kind == "knowledge":
        stmt = stmt.where(Intel.kind == "knowledge")
    else:
        return {"ok": True, "deleted": 0}
    rows = (await session.execute(stmt)).scalars().all()
    n = 0
    for it in rows:
        await session.delete(it)
        n += 1
    await session.commit()
    return {"ok": True, "deleted": n}


# ============ 知识库（kind='knowledge'）：手动增删改 / 同步种子 / 取全文 ============

def _knowledge_to_dict(it: Intel, with_content: bool = False) -> dict:
    pl = it.payload or {}
    d = {
        "id": it.id,
        "match_key": it.match_key or "",
        "category": pl.get("category", "user"),
        "origin": pl.get("origin", "user"),
        "name": pl.get("name", ""),
        "keyword": pl.get("keyword", ""),
        "summary": it.summary or "",
        "enabled": bool(pl.get("enabled", True)),
        "hit_count": it.hit_count or 1,
        "created_at": to_cst_iso(it.first_seen),
        "updated_at": to_cst_iso(it.last_seen),
    }
    if with_content:
        d["content"] = pl.get("content", "")
    return d


@router.get("/knowledge")
async def list_knowledge(
    category: str = Query("all"),
    q: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    """知识库列表：按分类(category)筛选 + 关键词搜索（summary/name/content）。"""
    stmt = select(Intel).where(Intel.kind == "knowledge").order_by(Intel.match_key)
    rows = (await session.execute(stmt)).scalars().all()
    needle = (q or "").strip().lower()
    out = []
    for it in rows:
        pl = it.payload or {}
        if category != "all" and pl.get("category") != category:
            continue
        if needle:
            blob = f"{it.match_key or ''} {it.summary or ''} {pl.get('name', '')} {pl.get('content', '')}".lower()
            if needle not in blob:
                continue
        out.append(_knowledge_to_dict(it, with_content=False))
    return out


@router.post("/knowledge/sync")
async def sync_knowledge(session: AsyncSession = Depends(get_session)):
    """把 knowledge/(rules+kb) 本地种子文件同步进知识库，同名已存在则跳过（保留用户编辑）。"""
    return await sync_kb_from_files(session)


@router.get("/knowledge/{knowledge_id}")
async def get_knowledge_detail(knowledge_id: str, session: AsyncSession = Depends(get_session)):
    """取单条知识库全文（前端详情/展开用）。"""
    it = await session.get(Intel, knowledge_id)
    if not it or it.kind != "knowledge":
        raise HTTPException(404, "知识不存在")
    return _knowledge_to_dict(it, with_content=True)


@router.post("/knowledge")
async def create_knowledge(
    payload: dict,
    session: AsyncSession = Depends(get_session),
):
    """前端手动添加一条知识库：{category, title, keyword, content, enabled}。"""
    title = str(payload.get("title", "")).strip() or "未命名知识"
    content = str(payload.get("content", "")).strip()
    if not content:
        raise HTTPException(422, "内容不能为空")
    category = str(payload.get("category", "user")).strip() or "user"
    from app.agents.knowledge import _seed_dedup
    import hashlib
    key = title
    it = Intel(
        kind="knowledge",
        match_key=key,
        # 用户条目 dedup_hash 前缀 kbu: 与 seed 的 kb: 区分开
        dedup_hash="kbu:" + hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest(),
        payload={
            "name": title,
            "category": category,
            "filename": "",
            "origin": "user",
            "content": content,
            "enabled": bool(payload.get("enabled", True)),
            "keyword": str(payload.get("keyword", "")).strip() or title,
        },
        summary=f"{title}（用户沉淀）"[:500],
        source_host="",
        source_task_id="",
        confidence="verified",
        hit_count=1,
    )
    session.add(it)
    await session.commit()
    return _knowledge_to_dict(it, with_content=True)


@router.put("/knowledge/{knowledge_id}")
async def update_knowledge(
    knowledge_id: str,
    payload: dict,
    session: AsyncSession = Depends(get_session),
):
    """编辑一条知识库：title / keyword / category / content / enabled。"""
    it = await session.get(Intel, knowledge_id)
    if not it or it.kind != "knowledge":
        raise HTTPException(404, "知识不存在")
    pl = dict(it.payload or {})
    if "title" in payload:
        title = str(payload["title"]).strip() or pl.get("name", "")
        pl["name"] = title
        pl["keyword"] = payload.get("keyword") or pl.get("keyword") or title
        it.match_key = title
        it.summary = f"{title}（{'用户沉淀' if pl.get('origin') == 'user' else '方法论' if pl.get('category') == 'rules' else '测试手册'}）"[:500]
    if "category" in payload:
        pl["category"] = str(payload["category"]).strip() or pl.get("category", "user")
    if "keyword" in payload:
        pl["keyword"] = str(payload["keyword"]).strip()
    if "content" in payload:
        c = str(payload["content"]).strip()
        if not c:
            raise HTTPException(422, "内容不能为空")
        pl["content"] = c
    if "enabled" in payload:
        pl["enabled"] = bool(payload["enabled"])
    it.payload = pl
    it.last_seen = it.last_seen
    await session.commit()
    return _knowledge_to_dict(it, with_content=True)
