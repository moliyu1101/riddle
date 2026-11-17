"""融合层 API：目标闸门 / 证据闸门 / 范围守卫 / 情报时间流 / 技能速查。

统一挂在 ``/api/fusion`` 前缀下，由 main.py 的全局鉴权中间件自动纳管
（observer 令牌同样走 protected_path 的既有规则）。本模块只做编排，
所有判定逻辑都在 app/fusion/ 的纯函数里，便于离线单测。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, FusionGoal, FusionGraphEdge, FusionGraphNode, FusionTraffic,
    Intel, Review, Target, Task, TaskEvent, to_cst_iso,
)
from app.db.session import get_session
from app.settings_service import effective_settings, update_settings
from app.fusion import (
    config, docx_report, evidence_gate, goal_gate, graphs,
    role_router, scope_guard, traffic_ledger, vulnintel,
)

router = APIRouter(prefix="/api/fusion", tags=["fusion"])


class EvidenceCheckReq(BaseModel):
    finding: dict[str, Any] | list[dict[str, Any]] = Field(default_factory=dict)


class ScopeCheckReq(BaseModel):
    target: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)


class GoalsReq(BaseModel):
    goals: list[dict[str, Any]] = Field(default_factory=list)


class IntelMatchReq(BaseModel):
    technologies: list[str] = Field(default_factory=list)


def _goal_to_dict(row: FusionGoal) -> dict:
    return {
        "id": row.id,
        "goal_key": row.goal_key,
        "title": row.title,
        "criteria": row.criteria,
        "kind": row.kind,
        "match": row.match_terms or [],
        "status": row.status,
        "evidence_ref": row.evidence_ref,
        "updated_at": to_cst_iso(row.updated_at),
    }


def _finding_to_dict(row: Finding) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "vuln_type": row.vuln_type,
        "severity_claimed": row.severity_claimed,
        "target_url": row.target_url,
        "owner": row.owner,
        "description": row.description,
        "affected_scope": row.affected_scope,
        "poc": row.poc,
        "poc_http": row.poc_http,
        "raw_request": row.raw_request,
        "raw_response": row.raw_response,
        "steps": row.steps or [],
        "evidence": row.evidence or {},
        "kill_chain": row.kill_chain or [],
    }


def _task_scope(task: Task | None) -> dict:
    if task is None:
        return {"roots": [], "sources": [], "cidrs": [], "company": ""}
    roots: list[str] = []
    for item in task.manual_targets or []:
        raw = item if isinstance(item, str) else str((item or {}).get("url") or (item or {}).get("host") or "")
        host = scope_guard.normalize_host(raw)
        if host:
            roots.append(scope_guard.root_domain(host))
    return {
        "roots": sorted(set(roots)),
        "sources": [],
        "cidrs": [],
        "company": task.name or "",
    }


@router.get("/status")
async def fusion_status(session: AsyncSession = Depends(get_session)):
    """融合层总览：生效配置 + 目标/情报计数。不回传任何密钥明文。"""
    goals = (await session.execute(select(func.count()).select_from(FusionGoal))).scalar() or 0
    feeds = (await session.execute(
        select(func.count()).select_from(Intel).where(Intel.kind == vulnintel.INTEL_KIND)
    )).scalar() or 0
    return {
        "config": config.public_config(),
        "goal_count": goals,
        "intel_feed_count": feeds,
        "role_routing": role_router.role_routing_table(),
        "modules": [
            {"id": "goal_gate", "name": "目标闸门", "desc": "目标 + 可核验验收标准 + 诚实终态"},
            {"id": "evidence_gate", "name": "证据闸门", "desc": "机械凭据门禁 + L1-L4 影响分级"},
            {"id": "scope_guard", "name": "范围守卫", "desc": "own/source/foreign 写回分类"},
            {"id": "vulnintel", "name": "情报时间流", "desc": "CVE/KEV 同步 + 指纹反向匹配"},
            {"id": "role_router", "name": "角色路由", "desc": "按角色配模型 + 技能速查注入"},
            {"id": "graphs", "name": "双图架构", "desc": "资产图 × 探索图 + 血缘回溯 + 覆盖度"},
            {"id": "traffic", "name": "流量留痕", "desc": "逐请求 JSONL + baseline/proof/verification/supporting 四类绑定"},
            {"id": "docx_report", "name": "公文报告", "desc": "封面/目录域/页眉页脚/证据链/修复路线图"},
        ],
    }


@router.get("/skill-index")
async def skill_index():
    entries = [dict(x) for x in role_router.load_skill_entries()]
    return {"count": len(entries), "entries": entries, "block": role_router.skill_index_block(entries)}


@router.post("/evidence/check")
async def evidence_check(req: EvidenceCheckReq):
    """试算一条或一批 finding 能否通过证据闸门；不落库、不拦截真实提交。"""
    if isinstance(req.finding, list):
        return evidence_gate.evaluate_findings(req.finding)
    return evidence_gate.check_finding(req.finding)


@router.post("/scope/check")
async def scope_check(req: ScopeCheckReq):
    scope = scope_guard.normalize_scope(req.scope)
    return scope_guard.check_writeback(req.target, scope)


@router.get("/goals/{task_id}")
async def list_goals(task_id: str, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(FusionGoal).where(FusionGoal.task_id == task_id).order_by(FusionGoal.created_at)
    )).scalars().all()
    return {"task_id": task_id, "goals": [_goal_to_dict(r) for r in rows]}


@router.put("/goals/{task_id}")
async def save_goals(task_id: str, req: GoalsReq, session: AsyncSession = Depends(get_session)):
    """整批替换目标；验收标准不合规直接 400，不留半成品。"""
    normalized, errors = goal_gate.validate_goals(req.goals)
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})
    task = (await session.execute(select(Task).where(Task.id == task_id))).scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    await session.execute(delete(FusionGoal).where(FusionGoal.task_id == task_id))
    for g in normalized:
        session.add(FusionGoal(
            task_id=task_id,
            goal_key=g["id"],
            title=g["title"],
            criteria=g["criteria"],
            kind=g["kind"],
            match_terms=g["match"],
            status=g["status"],
            evidence_ref=g["evidence_ref"],
        ))
    await session.commit()
    return {"ok": True, "task_id": task_id, "saved": len(normalized), "scope": _task_scope(task)}


@router.post("/goals/{task_id}/evaluate")
async def evaluate_goals(task_id: str, session: AsyncSession = Depends(get_session)):
    """用本任务已提交的 finding 逐条核对目标，返回诚实终态。"""
    goal_rows = (await session.execute(
        select(FusionGoal).where(FusionGoal.task_id == task_id)
    )).scalars().all()
    if not goal_rows:
        return {"task_id": task_id, "configured": False, "summary": "未设置目标", "terminal_state": "incomplete"}
    finding_rows = (await session.execute(
        select(Finding).where(Finding.task_id == task_id)
    )).scalars().all()
    goals = [{
        "id": r.goal_key, "title": r.title, "criteria": r.criteria, "kind": r.kind,
        "match": r.match_terms or [], "status": r.status, "evidence_ref": r.evidence_ref,
    } for r in goal_rows]
    result = goal_gate.evaluate(goals, [_finding_to_dict(f) for f in finding_rows])
    result.update({"task_id": task_id, "configured": True, "finding_count": len(finding_rows)})
    return result


@router.get("/intel/recent")
async def intel_recent(limit: int = Query(50, ge=1, le=200), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Intel).where(Intel.kind == vulnintel.INTEL_KIND).order_by(Intel.last_seen.desc()).limit(limit)
    )).scalars().all()
    return {"items": [{
        "cve_id": (r.payload or {}).get("cve_id", ""),
        "cvss": (r.payload or {}).get("cvss", 0),
        "kev": (r.payload or {}).get("kev", False),
        "products": (r.payload or {}).get("products", []),
        "match_key": r.match_key,
        "summary": r.summary,
        "last_seen": to_cst_iso(r.last_seen),
    } for r in rows]}


@router.post("/intel/sync")
async def intel_sync(session: AsyncSession = Depends(get_session)):
    """手动触发一次 CVE 时间流同步并落库；网络失败时明确回报，不静默。"""
    result = vulnintel.sync()
    if not result.get("rows"):
        return {**result, "stored": 0}
    stored = 0
    for row in result["rows"]:
        existing = (await session.execute(
            select(Intel).where(Intel.kind == vulnintel.INTEL_KIND, Intel.dedup_hash == row["dedup_hash"])
        )).scalar_one_or_none()
        if existing:
            existing.payload = row["payload"]
            existing.summary = row["summary"]
            existing.match_key = row["match_key"]
            existing.hit_count = (existing.hit_count or 1) + 1
        else:
            session.add(Intel(**row))
        stored += 1
    await session.commit()
    return {**result, "stored": stored}


@router.post("/intel/match")
async def intel_match(req: IntelMatchReq, session: AsyncSession = Depends(get_session)):
    """资产指纹 → CVE 反查，产出可注入 prompt 的 hint。"""
    rows = (await session.execute(
        select(Intel).where(Intel.kind == vulnintel.INTEL_KIND).limit(500)
    )).scalars().all()
    entries = [{
        "cve_id": (r.payload or {}).get("cve_id", ""),
        "cvss": (r.payload or {}).get("cvss", 0),
        "kev": (r.payload or {}).get("kev", False),
        "products": (r.payload or {}).get("products", []) + [r.match_key or ""],
        "summary": r.summary or "",
    } for r in rows]
    hints = vulnintel.match_fingerprint(entries, req.technologies)
    return {"count": len(hints), "hints": hints}


# ===========================================================================
# 后续模块：前端可写配置 / 双图架构 / 流量留痕 / 公文级报告
# ===========================================================================

class FusionConfigReq(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


class TrafficImportReq(BaseModel):
    task_id: str
    work_dir: str = ""


class TrafficBindReq(BaseModel):
    finding_id: str
    traffic_ids: list[str] = Field(default_factory=list)
    role: str = "supporting"


def _overlay() -> dict:
    raw = (effective_settings().get("defaults") or {}).get("fusion") or {}
    return raw if isinstance(raw, dict) else {}


def _require(module: str) -> None:
    """写操作前读开关：关闭时明确 409，避免前端点了没反应却找不到原因。

    只读接口（GET 图 / 列表 / 报告模型预览）不受开关影响，方便排障与取数。
    """
    cfg = config.load_config()
    enabled = {"graphs": cfg.graphs_enabled, "report": cfg.report_enabled}.get(module, True)
    if not enabled:
        raise HTTPException(status_code=409, detail=f"融合层模块 {module} 已在配置中关闭")


def _node_dict(row: FusionGraphNode) -> dict:
    return {"id": row.id, "graph": row.graph, "kind": row.kind, "label": row.label,
            "ref_id": row.ref_id, "payload": row.payload or {}}


def _edge_dict(row: FusionGraphEdge) -> dict:
    return {"id": row.id, "kind": row.kind, "src": row.src, "dst": row.dst}


def _traffic_dict(row: FusionTraffic) -> dict:
    return {"id": row.id, "role": row.role, "method": row.method, "url": row.url,
            "status_code": row.status_code, "request_head": row.request_head,
            "response_head": row.response_head, "body_sha256": row.body_sha256,
            "finding_id": row.finding_id, "created_at": to_cst_iso(row.created_at)}


def _discover_traffic_dirs() -> list[str]:
    """自动发现工作区里由 executor 写下的 fusion_traffic.jsonl 所在目录。"""
    import os
    from pathlib import Path
    roots = [os.getenv("WORKER_WORK_ROOT", ""), str(Path.cwd() / "data"), str(Path.cwd() / "work")]
    out: list[str] = []
    for raw in roots:
        if not raw:
            continue
        p = Path(raw)
        if not p.exists():
            continue
        try:
            for f in list(p.glob("**/" + traffic_ledger.JSONL_NAME))[:40]:
                out.append(str(f.parent))
        except OSError:
            continue
    return sorted(set(out))[:40]


@router.get("/config")
async def get_fusion_config():
    """当前生效配置 + DB 覆盖值；密钥只回显是否已配置。"""
    ov = _overlay()
    return {"config": config.public_config(), "overlay": ov, "source": "db" if ov else "env"}


@router.put("/config")
async def put_fusion_config(req: FusionConfigReq, session: AsyncSession = Depends(get_session)):
    """融合页保存配置：白名单收敛后写入 SystemSettings.defaults.fusion，并刷新缓存。"""
    patch = config.writable_patch(req.config)
    if not patch:
        raise HTTPException(status_code=400, detail="没有可保存的有效配置项")
    # defaults 是整键覆盖：先合并旧 overlay，保证只提交部分字段时不丢已有配置
    merged = {**_overlay(), **patch}
    await update_settings(session, {"defaults": {"fusion": merged}})
    return {"ok": True, "saved": patch, "overlay": merged, "config": config.public_config()}


@router.post("/graphs/{task_id}/rebuild")
async def rebuild_graph(task_id: str, session: AsyncSession = Depends(get_session)):
    """从主表旁路重建双图（幂等整批替换），不改任何主数据。"""
    _require("graphs")
    task = (await session.execute(select(Task).where(Task.id == task_id))).scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    targets = (await session.execute(select(Target).where(Target.task_id == task_id))).scalars().all()
    goal_rows = (await session.execute(select(FusionGoal).where(FusionGoal.task_id == task_id))).scalars().all()
    findings = (await session.execute(select(Finding).where(Finding.task_id == task_id))).scalars().all()
    events = (await session.execute(
        select(TaskEvent).where(TaskEvent.task_id == task_id).order_by(TaskEvent.id.desc()).limit(200)
    )).scalars().all()

    tdicts = [{"id": t.id, "url": t.url, "host": t.host, "ip": t.ip, "title": t.title} for t in targets]
    gdicts = [{"id": g.goal_key, "title": g.title, "criteria": g.criteria} for g in goal_rows]
    fdicts = [_finding_to_dict(f) for f in findings]
    edicts = [{"kind": e.kind, "message": e.message} for e in events]
    asset_nodes, asset_edges = graphs.asset_nodes(tdicts)
    explore_nodes, explore_edges, _ = graphs.exploration_nodes(gdicts, fdicts, edicts)
    # 覆盖边：已完成目标对应的 endpoint 节点记一条 covers
    for t in targets:
        if t.status not in ("done", "skipped"):
            continue
        host = scope_guard.normalize_host(t.host or t.url)
        ep = next((n for n in asset_nodes if n["kind"] == "endpoint" and n["label"].startswith(host)), None)
        if ep:
            asset_edges.append({"kind": "covers", "src": "coverage", "dst": ep["id"]})
    nodes = asset_nodes + explore_nodes
    edges = asset_edges + explore_edges

    await session.execute(delete(FusionGraphEdge).where(FusionGraphEdge.task_id == task_id))
    await session.execute(delete(FusionGraphNode).where(FusionGraphNode.task_id == task_id))
    for n in nodes:
        session.add(FusionGraphNode(task_id=task_id, **n))
    for e in edges:
        session.add(FusionGraphEdge(task_id=task_id, **{k: e[k] for k in ("kind", "src", "dst")}))
    await session.commit()
    return {"ok": True, "task_id": task_id, "nodes": len(nodes), "edges": len(edges),
            "coverage": graphs.coverage(nodes, edges)}


@router.get("/graphs/{task_id}")
async def get_graph(task_id: str, session: AsyncSession = Depends(get_session)):
    nodes = (await session.execute(select(FusionGraphNode).where(FusionGraphNode.task_id == task_id))).scalars().all()
    edges = (await session.execute(select(FusionGraphEdge).where(FusionGraphEdge.task_id == task_id))).scalars().all()
    nd, ed = [_node_dict(n) for n in nodes], [_edge_dict(e) for e in edges]
    return {"task_id": task_id, "nodes": nd, "edges": ed, "coverage": graphs.coverage(nd, ed),
            "asset_kinds": list(graphs.ASSET_KINDS), "edge_kinds": list(graphs.EDGE_KINDS)}


@router.get("/graphs/{task_id}/lineage")
async def graph_lineage(task_id: str, node_id: str = Query(""),
                        direction: str = Query("both", pattern="^(backward|forward|both)$"),
                        session: AsyncSession = Depends(get_session)):
    nodes = (await session.execute(select(FusionGraphNode).where(FusionGraphNode.task_id == task_id))).scalars().all()
    edges = (await session.execute(select(FusionGraphEdge).where(FusionGraphEdge.task_id == task_id))).scalars().all()
    return {"task_id": task_id, "node_id": node_id, "direction": direction,
            "chain": graphs.lineage([_node_dict(n) for n in nodes], [_edge_dict(e) for e in edges],
                                    node_id, direction=direction)}


@router.get("/traffic/discover")
async def traffic_discover():
    return {"dirs": _discover_traffic_dirs()}


@router.post("/traffic/import")
async def traffic_import(req: TrafficImportReq, session: AsyncSession = Depends(get_session)):
    """把 executor 写下的 JSONL 导入流量台账（按 sha256+url 幂等）。"""
    dirs = [req.work_dir] if req.work_dir else _discover_traffic_dirs()
    rows: list[dict] = []
    for d in dirs:
        rows.extend(traffic_ledger.read_jsonl(d))
    built = traffic_ledger.build_db_rows(rows, req.task_id)
    imported = 0
    for row in built:
        exists = (await session.execute(
            select(FusionTraffic.id).where(
                FusionTraffic.task_id == req.task_id,
                FusionTraffic.body_sha256 == row["body_sha256"],
                FusionTraffic.url == row["url"],
            )
        )).scalar_one_or_none()
        if exists:
            continue
        session.add(FusionTraffic(**row))
        imported += 1
    await session.commit()
    return {"ok": True, "scanned_dirs": dirs, "scanned_rows": len(rows),
            "unique_rows": len(built), "imported": imported}


@router.get("/traffic/{task_id}")
async def traffic_list(task_id: str, limit: int = Query(100, ge=1, le=500),
                       session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(FusionTraffic).where(FusionTraffic.task_id == task_id)
        .order_by(FusionTraffic.created_at.desc()).limit(limit)
    )).scalars().all()
    items = [_traffic_dict(r) for r in rows]
    grouped = {role: [i for i in items if i["role"] == role] for role in traffic_ledger.ROLES}
    return {"items": items, "count": len(items), "grouped": grouped}


@router.post("/traffic/bind")
async def traffic_bind(req: TrafficBindReq, session: AsyncSession = Depends(get_session)):
    exists = (await session.execute(
        select(Finding.id).where(Finding.id == req.finding_id)
    )).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    role = req.role if req.role in traffic_ledger.ROLES else "supporting"
    updated = 0
    for tid in req.traffic_ids:
        row = (await session.execute(select(FusionTraffic).where(FusionTraffic.id == tid))).scalar_one_or_none()
        if row:
            row.finding_id = req.finding_id
            row.role = role
            updated += 1
    await session.commit()
    return {"ok": True, "updated": updated, "role": role}


async def _build_report_model(session: AsyncSession, finding_id: str) -> dict:
    f = (await session.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
    if f is None:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    review = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    goals = (await session.execute(select(FusionGoal).where(FusionGoal.task_id == f.task_id))).scalars().all()
    gdicts = [{"id": g.goal_key, "title": g.title, "criteria": g.criteria, "kind": g.kind,
               "match": g.match_terms or [], "status": g.status} for g in goals]
    evaluation = goal_gate.evaluate(gdicts, [_finding_to_dict(f)]) if gdicts else {}
    trs = (await session.execute(
        select(FusionTraffic).where(FusionTraffic.finding_id == finding_id).limit(100)
    )).scalars().all()
    review_dict = None
    if review:
        review_dict = {"verdict": review.verdict, "severity_final": review.severity_final,
                      "reviewer_notes": review.reviewer_notes, "reproduced": review.reproduced}
    return docx_report.build_report_model(_finding_to_dict(f), review_dict, evaluation,
                                          [_traffic_dict(t) for t in trs],
                                          {"org": f.owner or "—"})


@router.get("/report/model/{finding_id}")
async def report_model(finding_id: str, session: AsyncSession = Depends(get_session)):
    _require("report")
    model = await _build_report_model(session, finding_id)
    return {"finding_id": finding_id, "model": model,
            "sections": ["执行摘要", "目标达成情况", "漏洞详情", "复现步骤与 PoC",
                         "流量证据链", "复测记录", "修复路线图", "附录"]}


@router.get("/report/docx/{finding_id}")
async def report_docx(finding_id: str, session: AsyncSession = Depends(get_session)):
    _require("report")
    model = await _build_report_model(session, finding_id)
    data = docx_report.build_public_docx_bytes(model)
    # Starlette 的响应头按 latin-1 编码：中文标题直接进 filename 会抛 UnicodeEncodeError
    # 让整个下载 500。这里与 findings.py 的导出保持一致，ASCII 名作兼容回退，
    # 另附 RFC 5987 的 filename* 保留中文名（前端 downloadFile 会优先解它）。
    from urllib.parse import quote

    ascii_name = f"riddle-report-{finding_id[:8]}.docx"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in model["title"])[:40].strip("_") or "report"
    quoted = quote(f"riddle_{safe}.docx")
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quoted}'},
    )
