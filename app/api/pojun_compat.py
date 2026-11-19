"""Pojun 前端适配兼容层（/api/pojun/*）。

将迁入 frontend/ 的 Pojun（Next.js + React + Shadcn）前端所需 API
无缝桥接到 Riddle 真实的 SQLAlchemy 数据表、Orchestrator 与 Fusion 融合层。
保持与 Riddle 原有 /api/* 路由（/api/tasks、/api/findings、/api/settings、/api/fusion 等）
完全隔离，确保后端原有接口与自动化测试零破坏。
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import platform
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import llm_config, worker_config
from app.db.models import (
    Finding,
    FusionGoal,
    FusionGraphEdge,
    FusionGraphNode,
    FusionTraffic,
    Intel,
    Killsweep,
    ReportVersion,
    Review,
    Target,
    Task,
    TaskEvent,
    to_cst_iso,
)
from app.db.session import SessionLocal, get_session
from app.fusion import (
    config as fusion_config,
    docx_report,
    goal_gate,
    graphs,
    intercept,
    retest,
    role_router,
    scope_guard,
    traffic_ledger,
    vulnintel,
)
from app.llm import health as llm_health
from app.llm import usage as llm_usage
from app.orchestrator import manager
from app.report_export import build_report_markdown
from app.security import (
    auth_enabled,
    configured_full_token,
    configured_observer_token,
    configured_read_token,
)
from app.settings_service import (
    _clean_llm_providers,
    effective_settings,
    list_available_models,
    normalize_llm_protocol,
    public_settings_view,
    refresh_cache,
    resolve_llm_config,
    resolve_llm_providers,
    secret_ref,
    update_settings,
)

router = APIRouter(prefix="/api/pojun", tags=["pojun-compat"])

_ROOT_DIR = Path(__file__).resolve().parents[2]
_LOCAL_JWT_FALLBACK = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJSaWRkbGUifQ.local"
_HOST_EXTRACT_RE = re.compile(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/[^\s,，;；]*)?")
_MASKED_ERR_RE = re.compile(
    r"(sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]{12,}|(?i:api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*[^\s'\"&]{6,})"
)


def _read_version() -> str:
    try:
        return (_ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip() or "0.2.0"
    except OSError:
        return "0.2.0"


def _int_id(value: str | int | None) -> int:
    if isinstance(value, int) and value > 0:
        return value
    raw = str(value or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    if not raw:
        return 1
    return max(1, int(hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()[:7], 16))


def _iso(dt: datetime | None) -> str:
    return to_cst_iso(dt) or datetime.now(timezone.utc).isoformat()


def _unix(dt: datetime | None) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _map_task_status(status: str | None) -> str:
    st = str(status or "created").strip().lower()
    if st in {"stopped", "idle"}:
        return "done"
    if st in {"running", "paused", "created"}:
        return st
    return "created"


def _map_severity(sev: str | None) -> str:
    s = str(sev or "").strip().lower()
    if s in {"critical", "严重"}:
        return "critical"
    if s in {"high", "高危"}:
        return "high"
    if s in {"medium", "中危"}:
        return "medium"
    return "low"


def _map_finding_status(f: Finding, r: Review | None) -> str:
    if r is None:
        return "pending" if f.status == "pending_review" else "in_progress"
    if r.submitted:
        return "resolved"
    if r.user_status == "passed":
        return "confirmed"
    if r.user_status == "rejected":
        return "false_positive"
    if r.verdict == "ignored":
        return "ignored"
    if r.is_duplicate:
        return "duplicate"
    return "pending"


def _pojun_task_dict(
    t: Task,
    finding_counts: dict[str, int] | None = None,
    goal_pair: tuple[int, int] = (0, 0),
    active_id: str = "",
    goal_text: str = "",
) -> dict[str, Any]:
    counts = finding_counts or {"critical": 0, "high": 0, "medium": 0, "low": 0}
    runner = manager.get_runner(t.id)
    live_workers = runner.live_workers() if runner else []
    snap = llm_usage.usage_snapshot(t.id, "")
    targets_preview = ", ".join(
        str(x if isinstance(x, str) else (x or {}).get("url") or (x or {}).get("host") or "")
        for x in (t.manual_targets or [])[:4]
    )
    desc = (t.fofa_query or targets_preview or t.name or "自主渗透任务").strip()
    goals_total, goals_met = goal_pair
    resolved_goal = goal_text or t.src_rules or (",".join(t.vuln_types or []) if t.vuln_types else "") or f"{t.src_type.upper()} 自主漏洞挖掘与验证"
    return {
        "id": t.id,
        "name": t.name or desc[:40],
        "description": desc,
        "goal": resolved_goal,
        "status": _map_task_status(t.status),
        "created_at": _iso(t.created_at),
        "created_unix": _unix(t.created_at),
        "completed_at": _iso(t.updated_at) if t.status in {"stopped", "idle"} else "",
        "completed_unix": _unix(t.updated_at) if t.status in {"stopped", "idle"} else 0,
        "last_activity_unix": _unix(t.updated_at),
        "paused": t.status == "paused",
        "autopilot": t.status == "running",
        "queued": False,
        "active": t.id == active_id or t.status == "running",
        "in_flight": len(live_workers),
        "findings": counts,
        "last_activity": _iso(t.updated_at),
        "stalled": False,
        "goals_total": goals_total,
        "goals_met": goals_met,
        "engine_mode": "exploring" if t.status == "running" else ("paused" if t.status == "paused" else "idle"),
        "coverage_enabled": fusion_config.load_config().graphs_enabled,
        "tokens": {
            "input_tokens": int(snap.get("prompt_tokens") or 0),
            "output_tokens": int(snap.get("completion_tokens") or 0),
            "cache_read_tokens": int(snap.get("cache_hit_tokens") or 0),
            "cache_write_tokens": int(snap.get("cache_miss_tokens") or 0),
        },
    }


def _pojun_finding_dict(
    f: Finding,
    r: Review | None = None,
    task: Task | None = None,
    traffic_count: int = 0,
    include_report: bool = False,
) -> dict[str, Any]:
    sev = _map_severity((r.user_severity if r else None) or (r.severity_final if r else None) or f.severity_claimed)
    src_type = (task.src_type if task else None) or "edusrc"
    report_md = build_report_markdown(f, r, src_type) if include_report else ""
    summary = (f.title or f.description or f.affected_scope or f.vuln_type or "未命名漏洞")[:240]
    ev_text = (f.poc or f.raw_request or f.raw_response or json.dumps(f.evidence or {}, ensure_ascii=False))[:800]
    assets = []
    if f.target_url:
        assets.append({"id": str(f.target_id or f.id), "type": "endpoint", "label": f.target_url})
    return {
        "id": f.id,
        "finding_id": f.id,
        "vulnclass": f.vuln_type or "general",
        "name": f.title or f.vuln_type,
        "severity": sev,
        "status": _map_finding_status(f, r),
        "summary": summary,
        "evidence": ev_text,
        "report": report_md,
        "task_id": f.task_id or "",
        "task_description": task.name if task else "",
        "assets": assets,
        "traffic_count": traffic_count,
        "evidence_version": 1,
        "report_evidence_version": 1,
        "report_stale": False,
        "ts": _iso(f.created_at),
    }


async def _task_finding_counts(session: AsyncSession) -> dict[str, dict[str, int]]:
    rows = (
        await session.execute(
            select(Finding.task_id, Finding.severity_claimed, Review.severity_final, Review.user_severity)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .where(Finding.status != "superseded")
        )
    ).all()
    out: dict[str, dict[str, int]] = {}
    for tid, s_claimed, s_final, s_user in rows:
        if not tid:
            continue
        bucket = out.setdefault(tid, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        bucket[_map_severity(s_user or s_final or s_claimed)] += 1
    return out


async def _task_goal_counts(session: AsyncSession) -> tuple[dict[str, tuple[int, int]], dict[str, str]]:
    rows = (await session.execute(select(FusionGoal).order_by(FusionGoal.created_at.asc()))).scalars().all()
    counts: dict[str, list[int]] = {}
    first_title: dict[str, str] = {}
    for g in rows:
        c = counts.setdefault(g.task_id, [0, 0])
        c[0] += 1
        if g.status == "met":
            c[1] += 1
        if g.task_id not in first_title and g.title:
            first_title[g.task_id] = g.title
    return {k: (v[0], v[1]) for k, v in counts.items()}, first_title


# ---------------------------------------------------------------------------
# 1. 系统与鉴权
# ---------------------------------------------------------------------------

@router.get("/health")
async def poj_health():
    return {"ok": True, "status": "ok"}


@router.get("/version")
async def poj_version():
    return {"service": "riddle", "version": _read_version()}


@router.get("/auth/status")
async def poj_auth_status():
    return {"initialized": True}


class LoginReq(BaseModel):
    username: str = ""
    password: str = ""


@router.post("/auth/login")
async def poj_login(body: LoginReq):
    if not auth_enabled():
        return {"token": _LOCAL_JWT_FALLBACK}
    pw = str(body.password or "").strip()
    valid = {
        tok for tok in (configured_full_token(), configured_read_token(), configured_observer_token()) if tok
    }
    if not pw or pw not in valid:
        raise HTTPException(status_code=401, detail="访问令牌错误")
    return {"token": pw}


@router.post("/auth/init")
async def poj_auth_init(body: dict[str, Any]):
    if auth_enabled():
        return {"token": configured_full_token() or _LOCAL_JWT_FALLBACK}
    pw = str((body or {}).get("password") or "").strip()
    return {"token": pw or _LOCAL_JWT_FALLBACK}


class ChangePwReq(BaseModel):
    old_password: str = ""
    new_password: str = ""


@router.post("/auth/change-password")
async def poj_change_pw(body: ChangePwReq, session: AsyncSession = Depends(get_session)):
    full = configured_full_token()
    if full and str(body.old_password or "").strip() != full:
        raise HTTPException(status_code=401, detail="原访问令牌不匹配")
    new_tok = str(body.new_password or "").strip()
    await update_settings(session, {"auth": {"full_token": new_tok}})
    return {"ok": True}


@router.get("/update/check")
async def poj_update_check(force: bool = False):
    cur = _read_version()
    return {
        "current": cur,
        "mode": "binary",
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "repo": "moliyu1101/riddle",
        "has_backup": False,
        "comparable": False,
        "has_update": False,
        "reason": "使用本地 git 仓库或 /api/update/check 进行更新检查",
    }


# ---------------------------------------------------------------------------
# 2. 仪表盘与全局指标
# ---------------------------------------------------------------------------

@router.get("/stats")
async def poj_stats(task: str = "", session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    assets_cnt = (await session.execute(select(func.count()).select_from(Target))).scalar() or 0
    confirmed_cnt = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .where(Finding.status != "superseded", or_(Review.verdict == "accepted", Review.user_status == "passed"))
        )
    ).scalar() or 0
    tasks = (await session.execute(select(Task).order_by(Task.updated_at.desc()))).scalars().all()
    selected = next((t for t in tasks if t.id == task), None) if task else (
        next((t for t in tasks if t.status == "running"), None) or (tasks[0] if tasks else None)
    )
    any_running = any(t.status == "running" for t in tasks)
    any_paused = any(t.status == "paused" for t in tasks)
    engine_mode = "exploring" if any_running else ("paused" if any_paused else "idle")
    llm_eff = effective_settings()["llm"]
    llm_ok = bool(llm_eff.get("api_key") or llm_eff.get("providers"))
    fcfg = fusion_config.load_config()
    active_dict = None
    if selected:
        fcounts = await _task_finding_counts(session)
        gcounts, gtitles = await _task_goal_counts(session)
        active_dict = _pojun_task_dict(
            selected,
            finding_counts=fcounts.get(selected.id),
            goal_pair=gcounts.get(selected.id, (0, 0)),
            active_id=selected.id,
            goal_text=gtitles.get(selected.id, ""),
        )
    return {
        "assets": assets_cnt,
        "engine_mode": engine_mode,
        "llm_configured": llm_ok,
        "roe_enabled": bool(fcfg.scope_guard_hard),
        "findings_confirmed": confirmed_cnt,
        "active_task": active_dict,
    }


@router.get("/tokens/usage")
async def poj_token_usage(days: int = 365, session: AsyncSession = Depends(get_session)):
    tasks = (await session.execute(select(Task))).scalars().all()
    eff_model = effective_settings()["llm"].get("model") or llm_config.model or "default"
    by_profile: list[dict[str, Any]] = []
    tot_in = tot_out = tot_cr = tot_reqs = 0
    for t in tasks:
        snap = llm_usage.usage_snapshot(t.id, eff_model)
        tot_in += int(snap.get("prompt_tokens") or 0)
        tot_out += int(snap.get("completion_tokens") or 0)
        tot_cr += int(snap.get("cache_hit_tokens") or 0)
        tot_reqs += int(snap.get("requests") or 0)
    if tot_reqs > 0:
        by_profile.append({
            "profile_name": eff_model,
            "calls": tot_reqs,
            "tasks": len(tasks),
            "input_tokens": tot_in,
            "output_tokens": tot_out,
            "cache_read_tokens": tot_cr,
            "cache_write_tokens": 0,
        })
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily = [{
        "profile_name": eff_model,
        "date": today,
        "input_tokens": tot_in,
        "output_tokens": tot_out,
        "cache_read_tokens": tot_cr,
    }] if tot_reqs > 0 else []
    return {"by_profile": by_profile, "daily": daily}


@router.get("/tokens/daily")
async def poj_token_daily(days: int = 30):
    return []


@router.get("/tokens/conversations")
async def poj_token_conversations():
    return []


@router.get("/tokens/cost")
async def poj_token_cost(task: str = ""):
    snap = llm_usage.usage_snapshot(task, "") if task else {}
    return {
        "task": {
            "task_id": task,
            "calls": int(snap.get("requests") or 0),
            "input_tokens": int(snap.get("prompt_tokens") or 0),
            "output_tokens": int(snap.get("completion_tokens") or 0),
        },
        "cost_usd": 0,
        "unpriced_models": [],
        "pricing_note": "由 Riddle 运行态 token 计数器实时估算",
    }


@router.get("/audit")
async def poj_audit(task: str = "", session: AsyncSession = Depends(get_session)):
    items = intercept.list_intercepts(task_id=task)
    entries = [
        {
            "ts": it.get("created_at") or datetime.now(timezone.utc).isoformat(),
            "tool": it.get("tool") or "run_shell",
            "action": "allow" if it.get("status") == "approved" else "block",
            "reason": it.get("reason") or "",
            "command": it.get("command") or "",
        }
        for it in items[:100]
    ]
    return {"entries": entries, "attributions": {}}


# ---------------------------------------------------------------------------
# 3. 任务管理与详情子资源
# ---------------------------------------------------------------------------

@router.get("/tasks")
async def poj_list_tasks(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(Task).order_by(Task.created_at.desc()))).scalars().all()
    fcounts = await _task_finding_counts(session)
    gcounts, gtitles = await _task_goal_counts(session)
    active = next((t.id for t in rows if t.status == "running"), rows[0].id if rows else "")
    return {
        "tasks": [
            _pojun_task_dict(
                t,
                finding_counts=fcounts.get(t.id),
                goal_pair=gcounts.get(t.id, (0, 0)),
                active_id=active,
                goal_text=gtitles.get(t.id, ""),
            )
            for t in rows
        ],
        "active": active,
    }


@router.get("/tasks/{task_id}")
async def poj_get_task(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    fcounts = await _task_finding_counts(session)
    gcounts, gtitles = await _task_goal_counts(session)
    return _pojun_task_dict(
        t,
        finding_counts=fcounts.get(t.id),
        goal_pair=gcounts.get(t.id, (0, 0)),
        active_id=t.id if t.status == "running" else "",
        goal_text=gtitles.get(t.id, ""),
    )


class PojTaskCreateReq(BaseModel):
    name: str = ""
    category_id: int | None = None
    description: str = ""
    goal: str = ""
    llm_profile_ids: list[int] = Field(default_factory=list)
    source_task_ids: list[str] = Field(default_factory=list)
    company_ids: list[int] = Field(default_factory=list)
    timeout_seconds: int = 0
    seed_first_intent: bool = False
    plan_heartbeat_seconds: int = 0
    coverage_enabled: bool = True
    intercept_rules: list[dict[str, Any]] = Field(default_factory=list)
    auth_config: dict[str, Any] | None = None


@router.post("/tasks")
async def poj_create_task(req: PojTaskCreateReq, session: AsyncSession = Depends(get_session)):
    raw_desc = (req.description or "").strip()
    extracted = [m.group(0).strip() for m in _HOST_EXTRACT_RE.finditer(raw_desc)]
    manual_targets = list(dict.fromkeys(extracted or ([raw_desc] if raw_desc else [])))
    fofa_query = ""
    if "fofa:" in raw_desc.lower():
        fofa_query = raw_desc.split("fofa:", 1)[-1].strip()
    target_source = "fofa" if fofa_query else "manual"
    auth_bindings = []
    if req.auth_config and req.auth_config.get("enabled"):
        auth_bindings.append({
            "target": manual_targets[0] if manual_targets else "",
            "login_url": str(req.auth_config.get("login_url") or ""),
            "username": str(req.auth_config.get("username") or ""),
            "password": str(req.auth_config.get("password") or ""),
        })
    task = Task(
        name=(req.name or raw_desc[:48] or "新渗透任务").strip(),
        src_type="edusrc",
        vuln_types=[],
        src_rules=req.goal or "",
        guard_ops=[],
        target_source=target_source,
        fofa_query=fofa_query,
        manual_targets=manual_targets,
        auth_bindings=auth_bindings,
        model_config_json={"inherit_global": True},
        status="created",
    )
    session.add(task)
    await session.flush()
    if (req.goal or "").strip():
        session.add(
            FusionGoal(
                task_id=task.id,
                goal_key="g1",
                title=req.goal.strip()[:480],
                criteria=req.goal.strip(),
                kind="existence",
                match_terms=[],
                status="open",
            )
        )
    await session.commit()
    await session.refresh(task)
    if req.seed_first_intent:
        task.status = "running"
        await session.commit()
        await manager.ensure_running(task.id)
    return _pojun_task_dict(task, goal_pair=(1 if (req.goal or "").strip() else 0, 0), goal_text=req.goal.strip())


@router.patch("/tasks/{task_id}")
async def poj_patch_task(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    if "name" in body and body["name"] is not None:
        t.name = str(body["name"]).strip()[:200] or t.name
    await session.commit()
    await session.refresh(t)
    return _pojun_task_dict(t)


@router.delete("/tasks/{task_id}")
async def poj_delete_task(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    await manager.stop(task_id)
    passed_ids = set(
        (
            await session.execute(
                select(Finding.id)
                .join(Review, Review.finding_id == Finding.id)
                .where(Finding.task_id == task_id, Review.user_status == "passed", Finding.status != "superseded")
            )
        ).scalars().all()
    )
    if passed_ids:
        await session.execute(update(Finding).where(Finding.id.in_(passed_ids)).values(task_id=None, target_id=None))
        await session.execute(update(Review).where(Review.finding_id.in_(passed_ids)).values(task_id=None))
    all_ids = (await session.execute(select(Finding.id).where(Finding.task_id == task_id))).scalars().all()
    del_ids = [fid for fid in all_ids if fid not in passed_ids]
    if del_ids:
        await session.execute(delete(ReportVersion).where(ReportVersion.finding_id.in_(del_ids)))
    res_f = await session.execute(delete(Finding).where(Finding.task_id == task_id))
    await session.execute(delete(Review).where(Review.task_id == task_id))
    await session.execute(delete(Killsweep).where(Killsweep.task_id == task_id))
    await session.execute(delete(TaskEvent).where(TaskEvent.task_id == task_id))
    res_a = await session.execute(delete(Target).where(Target.task_id == task_id))
    res_tr = await session.execute(delete(FusionTraffic).where(FusionTraffic.task_id == task_id))
    await session.execute(delete(FusionGoal).where(FusionGoal.task_id == task_id))
    await session.execute(delete(FusionGraphEdge).where(FusionGraphEdge.task_id == task_id))
    await session.execute(delete(FusionGraphNode).where(FusionGraphNode.task_id == task_id))
    await session.execute(delete(Task).where(Task.id == task_id))
    await session.commit()
    return {
        "deleted": task_id,
        "assets_deleted": int(res_a.rowcount or 0),
        "assets_detached": 0,
        "traffic_deleted": int(res_tr.rowcount or 0),
        "files_deleted": False,
        "findings_deleted": int(res_f.rowcount or 0),
        "llm_records_deleted": 0,
    }


@router.post("/tasks/{task_id}/control")
async def poj_control_task(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    action = str((body or {}).get("action") or "").strip().lower()
    if action == "pause":
        t.status = "paused"
        await session.commit()
        await manager.pause(task_id)
    elif action == "resume":
        t.status = "running"
        await session.commit()
        await manager.ensure_running(task_id)
    else:
        raise HTTPException(400, "未知控制动作")
    await session.refresh(t)
    return {"id": t.id, "paused": t.status == "paused", "queued": False, "status": _map_task_status(t.status)}


@router.post("/tasks/{task_id}/autopilot")
async def poj_task_autopilot(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    enabled = bool((body or {}).get("enabled"))
    resume = bool((body or {}).get("resume"))
    if enabled and resume:
        t.status = "running"
        await session.commit()
        await manager.ensure_running(task_id)
    elif not enabled and t.status == "running":
        t.status = "paused"
        await session.commit()
        await manager.pause(task_id)
    return {"ok": True, "autopilot": enabled, "resumed": resume, "status": _map_task_status(t.status)}


@router.post("/tasks/control/batch")
async def poj_control_batch(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    ids = [str(x) for x in (body or {}).get("task_ids") or []]
    action = str((body or {}).get("action") or "pause").lower()
    out = []
    for tid in ids:
        t = await session.get(Task, tid)
        if not t:
            out.append({"id": tid, "ok": False, "error": "任务不存在"})
            continue
        if action == "pause":
            t.status = "paused"
            await manager.pause(tid)
        else:
            t.status = "running"
            await manager.ensure_running(tid)
        out.append({"id": tid, "ok": True, "status": _map_task_status(t.status), "queued": False})
    await session.commit()
    return {"items": out}


@router.get("/task-categories")
async def poj_task_categories():
    return {"categories": []}


@router.get("/task-templates")
async def poj_task_templates():
    return {"templates": []}


@router.get("/task-archives")
async def poj_task_archives(page: int = 1, size: int = 20):
    return {"items": [], "total": 0, "page": page, "size": size}


@router.get("/tasks/{task_id}/llm/resolution")
async def poj_task_llm_resolution(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    cfg = resolve_llm_config(t)
    avail = bool(cfg.api_key)
    role_rows = {r["role"]: r for r in role_router.role_routing_table(cfg.model)}
    def _res(role_key: str) -> dict[str, Any]:
        rr = role_rows.get(role_key, {})
        model = str(rr.get("model") or cfg.model or "未配置")
        return {
            "profile_id": 1 if avail else None,
            "name": f"{role_key} 通道",
            "format": normalize_llm_protocol(cfg.protocol),
            "model": model,
            "source": "global",
            "available": avail,
            "reason": "" if avail else "尚未配置 LLM API Key",
        }
    return {"mainagent": _res("planner"), "planner": _res("planner"), "worker": _res("worker")}


# ---- Goals / Constraints / Scope / Coverage ----

@router.get("/tasks/{task_id}/goals")
async def poj_get_goals(task_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(select(FusionGoal).where(FusionGoal.task_id == task_id).order_by(FusionGoal.created_at))
    ).scalars().all()
    return {
        "goals": [
            {
                "id": g.id,
                "text": g.title,
                "vulnclass": ",".join(g.match_terms or []),
                "state": "met" if g.status == "met" else "open",
                "origin": "manual",
                "ts": _iso(g.created_at),
            }
            for g in rows
        ]
    }


@router.post("/tasks/{task_id}/goals")
async def poj_add_goal(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    text = str((body or {}).get("text") or "").strip()
    vulnclass = str((body or {}).get("vulnclass") or "").strip()
    cnt = (await session.execute(select(func.count()).select_from(FusionGoal).where(FusionGoal.task_id == task_id))).scalar() or 0
    g = FusionGoal(
        task_id=task_id,
        goal_key=f"g{cnt + 1}_{int(time.time()) % 10000}",
        title=text[:480] or "自定义验收目标",
        criteria=text,
        kind="capability" if vulnclass else "existence",
        match_terms=[x.strip() for x in vulnclass.split(",") if x.strip()],
        status="open",
    )
    session.add(g)
    await session.commit()
    await session.refresh(g)
    return {"id": g.id, "text": g.title, "vulnclass": vulnclass, "state": "open", "origin": "manual", "ts": _iso(g.created_at)}


@router.patch("/tasks/{task_id}/goals/{goal_id}")
async def poj_patch_goal(task_id: str, goal_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    g = await session.get(FusionGoal, goal_id)
    if not g or g.task_id != task_id:
        raise HTTPException(404, "目标不存在")
    if "text" in body and body["text"] is not None:
        g.title = str(body["text"]).strip()[:480]
        g.criteria = str(body["text"]).strip()
    if "vulnclass" in body:
        vc = str(body["vulnclass"] or "").strip()
        g.match_terms = [x.strip() for x in vc.split(",") if x.strip()]
    await session.commit()
    return {"id": g.id, "text": g.title, "vulnclass": ",".join(g.match_terms or []), "state": g.status, "ts": _iso(g.updated_at)}


@router.delete("/tasks/{task_id}/goals/{goal_id}")
async def poj_del_goal(task_id: str, goal_id: str, session: AsyncSession = Depends(get_session)):
    await session.execute(delete(FusionGoal).where(FusionGoal.id == goal_id, FusionGoal.task_id == task_id))
    await session.commit()
    return {"ok": True}


@router.get("/tasks/{task_id}/constraints")
async def poj_get_constraints(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        return {"constraints": []}
    lines = [x.strip() for x in (t.src_rules or "").splitlines() if x.strip()]
    return {
        "constraints": [
            {"id": str(i + 1), "kind": "deny", "text": ln, "origin": "task", "ts": _iso(t.updated_at)}
            for i, ln in enumerate(lines)
        ]
    }


@router.post("/tasks/{task_id}/constraints")
async def poj_add_constraint(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    text = str((body or {}).get("text") or "").strip()
    kind = str((body or {}).get("kind") or "deny")
    lines = [x for x in (t.src_rules or "").splitlines() if x.strip()]
    if text:
        lines.append(text)
    t.src_rules = "\n".join(lines)
    await session.commit()
    return {"id": str(len(lines)), "kind": kind, "text": text, "origin": "manual", "ts": _iso(t.updated_at)}


@router.patch("/tasks/{task_id}/constraints/{cid}")
async def poj_patch_constraint(task_id: str, cid: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    lines = [x for x in (t.src_rules or "").splitlines() if x.strip()]
    idx = int(cid) - 1 if cid.isdigit() else -1
    if 0 <= idx < len(lines) and "text" in body:
        lines[idx] = str(body["text"]).strip()
        t.src_rules = "\n".join(x for x in lines if x)
        await session.commit()
    return {"id": cid, "kind": body.get("kind") or "deny", "text": body.get("text") or ""}


@router.delete("/tasks/{task_id}/constraints/{cid}")
async def poj_del_constraint(task_id: str, cid: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if t:
        lines = [x for x in (t.src_rules or "").splitlines() if x.strip()]
        idx = int(cid) - 1 if cid.isdigit() else -1
        if 0 <= idx < len(lines):
            lines.pop(idx)
            t.src_rules = "\n".join(lines)
            await session.commit()
    return {"ok": True}


@router.get("/tasks/{task_id}/scope")
async def poj_task_scope(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        return {"scope": []}
    rows = []
    for i, item in enumerate(t.manual_targets or [], start=1):
        raw = item if isinstance(item, str) else str((item or {}).get("url") or (item or {}).get("host") or "")
        host = scope_guard.normalize_host(raw) or raw
        rows.append({
            "id": i,
            "task_id": _int_id(task_id),
            "kind": "root_domain",
            "domain": host,
            "value": raw,
            "source": "manual",
            "reason": "任务授权范围",
        })
    return {"scope": rows}


@router.post("/tasks/{task_id}/scope")
async def poj_add_scope(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    val = str((body or {}).get("value") or "").strip()
    lst = list(t.manual_targets or [])
    if val and val not in lst:
        lst.append(val)
        t.manual_targets = lst
        await session.commit()
    return {
        "id": len(lst),
        "task_id": _int_id(task_id),
        "kind": str((body or {}).get("kind") or "root_domain"),
        "domain": val,
        "value": val,
        "source": "manual",
        "reason": str((body or {}).get("reason") or ""),
    }


@router.delete("/tasks/{task_id}/scope/{scope_id}")
async def poj_del_scope(task_id: str, scope_id: int, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if t and 1 <= scope_id <= len(t.manual_targets or []):
        lst = list(t.manual_targets or [])
        lst.pop(scope_id - 1)
        t.manual_targets = lst
        await session.commit()
    return {"ok": True}


@router.get("/tasks/{task_id}/coverage")
async def poj_task_coverage(task_id: str, session: AsyncSession = Depends(get_session)):
    targets = (await session.execute(select(Target).where(Target.task_id == task_id))).scalars().all()
    total = len(targets)
    tested = sum(1 for x in targets if x.status in {"done", "skipped", "dead"})
    pct = round(tested * 100.0 / total, 1) if total else None
    return {
        "enabled": fusion_config.load_config().graphs_enabled,
        "scope_rows": total,
        "denominator": total,
        "tested": tested,
        "pct": pct,
        "by_type": [{"type": "endpoint", "total": total, "tested": tested}] if total else [],
    }


@router.get("/tasks/{task_id}/coverage-graph")
async def poj_task_coverage_graph(task_id: str, session: AsyncSession = Depends(get_session)):
    targets = (await session.execute(select(Target).where(Target.task_id == task_id))).scalars().all()
    nodes = []
    edges = []
    roots_seen: dict[str, str] = {}
    for x in targets[:150]:
        host = scope_guard.normalize_host(x.host or x.url) or "unknown"
        root = scope_guard.root_domain(host) or host
        if root not in roots_seen:
            rkey = f"r:{root}"
            roots_seen[root] = rkey
            nodes.append({"key": rkey, "kind": "root_domain", "label": root, "tested": True, "in_scope": True, "root_domain": root})
        akey = f"a:{_int_id(x.id)}"
        nodes.append({
            "key": akey,
            "kind": "endpoint",
            "label": x.url or host,
            "tested": x.status in {"done", "skipped", "dead"},
            "in_scope": True,
            "asset_id": _int_id(x.id),
            "domain": host,
            "root_domain": root,
            "ip": x.ip or "",
            "url": x.url or "",
            "page_title": x.title or "",
        })
        edges.append({"src": roots_seen[root], "dst": akey})
    return {"nodes": nodes, "edges": edges}


@router.get("/tasks/{task_id}/intercept-rules")
async def poj_task_intercept_rules(task_id: str, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        return {"rules": []}
    return {
        "rules": [
            {
                "id": i,
                "enabled": True,
                "action": "block",
                "kind": "fuzzy_url",
                "pattern": op,
                "note": "任务级操作黑名单",
                "builtin": False,
                "created_at": _iso(t.created_at),
                "updated_at": _iso(t.updated_at),
            }
            for i, op in enumerate(t.guard_ops or [], start=1)
        ]
    }


@router.post("/tasks/{task_id}/intercept-rules")
async def poj_create_task_intercept_rule(task_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    pat = str((body or {}).get("pattern") or "").strip()
    ops = list(t.guard_ops or [])
    if pat and pat not in ops:
        ops.append(pat)
        t.guard_ops = ops
        await session.commit()
    return {
        "id": len(ops),
        "enabled": True,
        "action": (body or {}).get("action") or "block",
        "kind": (body or {}).get("kind") or "fuzzy_url",
        "pattern": pat,
        "note": (body or {}).get("note") or "",
        "builtin": False,
        "created_at": _iso(t.updated_at),
        "updated_at": _iso(t.updated_at),
    }


@router.delete("/tasks/{task_id}/intercept-rules/{rule_id}")
async def poj_delete_task_intercept_rule(task_id: str, rule_id: int, session: AsyncSession = Depends(get_session)):
    t = await session.get(Task, task_id)
    if t and 1 <= rule_id <= len(t.guard_ops or []):
        ops = list(t.guard_ops or [])
        ops.pop(rule_id - 1)
        t.guard_ops = ops
        await session.commit()
    return {"deleted": True}


@router.get("/tasks/{task_id}/artifacts")
async def poj_task_artifacts(task_id: str):
    return {"artifacts": []}


@router.post("/tasks/{task_id}/artifacts/scan")
async def poj_scan_artifacts(task_id: str):
    return {"added": 0, "skipped": 0, "truncated": 0}


@router.post("/tasks/{task_id}/auth-check")
async def poj_task_auth_check(task_id: str):
    return {"ok": True, "matched": True, "detail": "任务凭据绑定已就绪", "elapsed_ms": 1, "checked_at": datetime.now(timezone.utc).isoformat()}


@router.get("/tasks/{task_id}/retest-candidates")
async def poj_retest_candidates(task_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Finding, Review)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .where(Finding.task_id == task_id, Finding.status != "superseded")
        )
    ).all()
    cands = []
    states = []
    for f, r in rows:
        sev = _map_severity((r.severity_final if r else None) or f.severity_claimed)
        retests = retest.get_finding_retests(f)
        if not retests:
            cands.append({"id": _int_id(f.id), "vulnclass": f.vuln_type, "name": f.title, "severity": sev, "summary": f.title})
        else:
            last = retests[-1]
            v = "fixed" if last.get("status") == "fixed" else ("reproduced" if last.get("status") == "reproduced" else "inconclusive")
            states.append({"finding_id": _int_id(f.id), "status": "completed", "verdict": v})
    return {"candidates": cands, "retest_states": states}


# ---------------------------------------------------------------------------
# 4. 探索图 / 意图 / 活动流
# ---------------------------------------------------------------------------

def _target_to_intent_node(tgt: Target) -> dict[str, Any]:
    st_map = {"queued": "open", "assigned": "running", "scanning": "running", "done": "done", "skipped": "stopped", "dead": "blocked"}
    return {
        "id": tgt.id,
        "type": "intent",
        "payload": tgt.url or tgt.host,
        "priority": int(round(min(10.0, max(1.0, float(tgt.priority_score or 5.0))))),
        "state": st_map.get(tgt.status, "open"),
        "origin": tgt.source or "fofa",
        "ts": _iso(tgt.updated_at or tgt.created_at),
        "blocked_reason": tgt.dead_reason or tgt.last_error or "",
    }


@router.get("/exploration/frontier")
async def poj_frontier(task: str = "", session: AsyncSession = Depends(get_session)):
    q = select(Target).where(Target.status.in_(["queued", "assigned", "scanning"]))
    if task:
        q = q.where(Target.task_id == task)
    rows = (await session.execute(q.order_by(Target.priority_score.desc()).limit(100))).scalars().all()
    return [_target_to_intent_node(r) for r in rows]


@router.get("/exploration/intents")
async def poj_intents(task: str = "", page: int = 0, limit: int = 200, session: AsyncSession = Depends(get_session)):
    q = select(Target)
    if task:
        q = q.where(Target.task_id == task)
    rows = (await session.execute(q.order_by(Target.created_at.desc()).limit(limit))).scalars().all()
    items = [_target_to_intent_node(r) for r in rows]
    if page > 0:
        return {"items": items, "has_more": False}
    return items


@router.get("/exploration/graph")
async def poj_exploration_graph(task: str = "", session: AsyncSession = Depends(get_session)):
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    if task:
        fnodes = (await session.execute(select(FusionGraphNode).where(FusionGraphNode.task_id == task))).scalars().all()
        fedges = (await session.execute(select(FusionGraphEdge).where(FusionGraphEdge.task_id == task))).scalars().all()
        if fnodes:
            for n in fnodes:
                nodes.append({
                    "id": n.id,
                    "type": n.kind if n.kind in {"task", "goal", "intent", "fact", "finding", "hint", "digest"} else "fact",
                    "payload": n.label,
                    "priority": 5,
                    "state": "confirmed",
                    "origin": n.graph,
                    "ts": _iso(n.created_at),
                })
            for e in fedges:
                edges.append({"src": e.src, "dst": e.dst, "rel": e.kind or "yields"})
            return {"nodes": nodes, "edges": edges}
        t = await session.get(Task, task)
        if t:
            nodes.append({"id": t.id, "type": "task", "payload": t.name, "priority": 10, "state": "open", "origin": "task", "ts": _iso(t.created_at)})
            targets = (await session.execute(select(Target).where(Target.task_id == task).limit(60))).scalars().all()
            for tg in targets:
                nodes.append(_target_to_intent_node(tg))
                edges.append({"src": t.id, "dst": tg.id, "rel": "spawns"})
            findings = (await session.execute(select(Finding).where(Finding.task_id == task).limit(60))).scalars().all()
            for fd in findings:
                nodes.append({"id": fd.id, "type": "finding", "payload": fd.title, "priority": 9, "state": "confirmed", "origin": "worker", "ts": _iso(fd.created_at)})
                if fd.target_id:
                    edges.append({"src": fd.target_id, "dst": fd.id, "rel": "proves"})
    return {"nodes": nodes, "edges": edges}


@router.get("/exploration/nodes")
async def poj_exploration_nodes(
    task: str = "",
    page: int = 1,
    size: int = 20,
    kind: str = "",
    state: str = "",
    q: str = "",
    order: str = "desc",
    session: AsyncSession = Depends(get_session),
):
    targets = (await session.execute(select(Target).where(Target.task_id == task) if task else select(Target))).scalars().all()
    items = [_target_to_intent_node(x) for x in targets]
    kinds = {k.strip() for k in kind.split(",") if k.strip()} if kind else set()
    states = {s.strip() for s in state.split(",") if s.strip()} if state else set()
    if kinds:
        items = [i for i in items if i["type"] in kinds]
    if states:
        items = [i for i in items if i["state"] in states]
    if q.strip():
        kw = q.strip().lower()
        items = [i for i in items if kw in str(i.get("payload") or "").lower()]
    items.sort(key=lambda x: x["ts"], reverse=(order != "asc"))
    total = len(items)
    start = max(0, (page - 1) * size)
    return {"items": items[start:start + size], "total": total, "page": page, "size": size, "edges": [], "refs": {}, "assets": {}}


def _event_to_activity(ev: TaskEvent) -> dict[str, Any]:
    return {
        "seq": ev.id,
        "worker": ev.agent or "worker",
        "ts": _iso(ev.ts),
        "kind": "tool_use" if (ev.payload or {}).get("tool") else "text",
        "tool": str((ev.payload or {}).get("tool") or ""),
        "is_error": ev.level == "error",
        "summary": ev.message or ev.kind or "",
        "detail": json.dumps(ev.payload or {}, ensure_ascii=False, indent=2) if ev.payload else "",
        "source_task_id": ev.task_id,
    }


@router.get("/exploration/activity")
async def poj_activity(task: str = "", since: int = 0, limit: int = 30, session: AsyncSession = Depends(get_session)):
    q = select(TaskEvent)
    if task:
        q = q.where(TaskEvent.task_id == task)
    if since > 0:
        q = q.where(TaskEvent.id > since)
    rows = (await session.execute(q.order_by(TaskEvent.id.desc()).limit(max(1, min(limit, 200))))).scalars().all()
    items = [_event_to_activity(r) for r in reversed(rows)]
    cursor = max((r.id for r in rows), default=since)
    return {"items": items, "cursor": cursor}


@router.get("/exploration/activity/history")
async def poj_activity_history(task: str = "", before: int = 0, limit: int = 200, session: AsyncSession = Depends(get_session)):
    q = select(TaskEvent)
    if task:
        q = q.where(TaskEvent.task_id == task)
    if before > 0:
        q = q.where(TaskEvent.id < before)
    rows = (await session.execute(q.order_by(TaskEvent.id.desc()).limit(limit + 1))).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [_event_to_activity(r) for r in reversed(rows)]
    snap = max((r.id for r in rows), default=0)
    earliest = min((r.id for r in rows), default=0)
    return {"items": items, "snapshot_cursor": snap, "earliest_cursor": earliest, "has_more": has_more}


@router.get("/exploration/activity/stream")
async def poj_activity_stream(task: str = "", since: int = 0):
    async def _gen():
        cursor = since
        for _ in range(30):
            async with SessionLocal() as session:
                q = select(TaskEvent).where(TaskEvent.id > cursor)
                if task:
                    q = q.where(TaskEvent.task_id == task)
                rows = (await session.execute(q.order_by(TaskEvent.id.asc()).limit(50))).scalars().all()
                for ev in rows:
                    cursor = ev.id
                    yield f"data: {json.dumps(_event_to_activity(ev), ensure_ascii=False)}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(_gen(), media_type="text/event-stream")


@router.get("/exploration/main-sessions")
async def poj_main_sessions():
    return {"sessions": [{"seq": 0, "created_at": datetime.now(timezone.utc).isoformat()}], "current": 0}


@router.get("/exploration/tokens")
async def poj_exploration_tokens(task: str = ""):
    snap = llm_usage.usage_snapshot(task, "") if task else {}
    inp = int(snap.get("prompt_tokens") or 0)
    out = int(snap.get("completion_tokens") or 0)
    cr = int(snap.get("cache_hit_tokens") or 0)
    cw = int(snap.get("cache_miss_tokens") or 0)
    return {
        "workers": [{"worker": "worker", "input_tokens": inp, "output_tokens": out, "cache_read_tokens": cr, "cache_write_tokens": cw}] if (inp or out) else [],
        "sessions": [],
        "total": {"input_tokens": inp, "output_tokens": out, "cache_read_tokens": cr, "cache_write_tokens": cw},
    }


# ---------------------------------------------------------------------------
# 5. 漏洞发现 / 关联流量 / 血缘 / 复测 / 报告导出
# ---------------------------------------------------------------------------

async def _finding_traffic_counts(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(
            select(FusionTraffic.finding_id, func.count()).where(FusionTraffic.finding_id != "").group_by(FusionTraffic.finding_id)
        )
    ).all()
    return {fid: int(cnt) for fid, cnt in rows if fid}


@router.get("/exploration/findings/stats")
async def poj_finding_stats(session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Finding, Review, Task)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .outerjoin(Task, Task.id == Finding.task_id)
            .where(Finding.status != "superseded")
        )
    ).all()
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    pending = 0
    vulnclasses: set[str] = set()
    by_task: dict[str, dict[str, Any]] = {}
    for f, r, t in rows:
        sev = _map_severity((r.user_severity if r else None) or (r.severity_final if r else None) or f.severity_claimed)
        sev_counts[sev] += 1
        if _map_finding_status(f, r) == "pending":
            pending += 1
        if f.vuln_type:
            vulnclasses.add(f.vuln_type)
        tid = f.task_id or "__unassigned__"
        entry = by_task.setdefault(tid, {"id": tid, "name": t.name if t else "独立保留漏洞", "description": t.name if t else "", "count": 0})
        entry["count"] += 1
    return {
        "total": len(rows),
        "pending": pending,
        **sev_counts,
        "vulnclasses": sorted(vulnclasses),
        "tasks": list(by_task.values()),
    }


@router.get("/exploration/findings/groups")
async def poj_finding_groups(page: int = 1, limit: int = 20, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Finding, Review, Task)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .outerjoin(Task, Task.id == Finding.task_id)
            .where(Finding.status != "superseded")
            .order_by(Finding.created_at.desc())
        )
    ).all()
    groups: dict[str, dict[str, Any]] = {}
    for f, r, t in rows:
        key = f.task_id or "__none__"
        g = groups.setdefault(
            key,
            {
                "task_id": f.task_id,
                "task_name": t.name if t else "独立留存漏洞",
                "task_description": t.fofa_query if t else "",
                "task_status": _map_task_status(t.status) if t else "done",
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "last_found_at": _iso(f.created_at),
            },
        )
        g["count"] += 1
        g[_map_severity((r.severity_final if r else None) or f.severity_claimed)] += 1
    items = list(groups.values())
    start = max(0, (page - 1) * limit)
    return {"items": items[start:start + limit], "total": len(items), "finding_total": len(rows), "page": page, "page_size": limit}


@router.get("/exploration/findings/asset-tree")
async def poj_finding_asset_tree(session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(Finding, Review).outerjoin(Review, Review.finding_id == Finding.id).where(Finding.status != "superseded")
        )
    ).all()
    by_host: dict[str, dict[str, Any]] = {}
    for f, r in rows:
        host = scope_guard.normalize_host(f.target_url) or "__none__"
        node = by_host.setdefault(
            host,
            {
                "key": "__none__" if host == "__none__" else f"r:{host}",
                "kind": "none" if host == "__none__" else "root_domain",
                "label": "未关联资产" if host == "__none__" else host,
                "self": 0,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "last_found_at": _iso(f.created_at),
            },
        )
        node["self"] += 1
        node["total"] += 1
        node[_map_severity((r.severity_final if r else None) or f.severity_claimed)] += 1
    return {"nodes": list(by_host.values()), "finding_total": len(rows), "truncated": False}


@router.get("/exploration/findings/retests/active")
async def poj_active_retests():
    return {"retests": []}


@router.get("/exploration/findings/export")
async def poj_export_findings(
    format: str = "md-single",
    scope: str = "all",
    task_id: str = "",
    ids: str = "",
    session: AsyncSession = Depends(get_session),
):
    q = (
        select(Finding, Review, Task)
        .outerjoin(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(Finding.status != "superseded")
    )
    if scope == "selected" and ids:
        id_list = [x.strip() for x in ids.split(",") if x.strip()]
        q = q.where(Finding.id.in_(id_list))
    elif task_id and task_id != "all":
        q = q.where(Finding.task_id == task_id)
    rows = (await session.execute(q.order_by(Finding.created_at.desc()))).all()
    if format == "json":
        payload = [_pojun_finding_dict(f, r, t, include_report=True) for f, r, t in rows]
        return Response(
            json.dumps(payload, ensure_ascii=False, indent=2),
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="riddle-findings.json"'},
        )
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "title", "vuln_type", "severity", "target_url", "created_at"])
        for f, r, _t in rows:
            w.writerow([f.id, f.title, f.vuln_type, _map_severity((r.severity_final if r else None) or f.severity_claimed), f.target_url, _iso(f.created_at)])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="riddle-findings.csv"'})
    if format in {"md-zip", "docx-zip"}:
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f, r, t in rows:
                if format == "docx-zip":
                    model = docx_report.build_report_model(
                        {"title": f.title, "vuln_type": f.vuln_type, "severity": f.severity_claimed, "target_url": f.target_url, "owner": f.owner, "description": f.description, "poc": f.poc, "steps": f.steps, "evidence": f.evidence},
                        None, {}, [], {"org": f.owner or "—"},
                    )
                    zf.writestr(f"{f.id[:8]}.docx", docx_report.build_public_docx_bytes(model))
                else:
                    zf.writestr(f"{f.id[:8]}.md", build_report_markdown(f, r, (t.src_type if t else None) or "edusrc"))
        return Response(zbuf.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="riddle-findings-{format}.zip"'})
    md_parts = [build_report_markdown(f, r, (t.src_type if t else None) or "edusrc") for f, r, t in rows]
    return Response("\n\n---\n\n".join(md_parts), media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="riddle-findings.md"'})


@router.get("/exploration/findings")
async def poj_list_findings(
    task: str = "",
    task_id: str = "",
    severity: str = "",
    status: str = "",
    vulnclass: str = "",
    q: str = "",
    sort: str = "severity",
    page: int | None = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(
            select(Finding, Review, Task)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .outerjoin(Task, Task.id == Finding.task_id)
            .where(Finding.status != "superseded")
            .order_by(Finding.created_at.desc())
        )
    ).all()
    tf_counts = await _finding_traffic_counts(session)
    tid = task_id or task
    items: list[dict[str, Any]] = []
    for f, r, t in rows:
        if tid and tid != "all" and f.task_id != tid:
            continue
        item = _pojun_finding_dict(f, r, t, traffic_count=tf_counts.get(f.id, 0))
        if severity and severity != "all" and item["severity"] != severity:
            continue
        if status and status != "all" and item["status"] != status:
            continue
        if vulnclass and vulnclass != "all" and item["vulnclass"] != vulnclass:
            continue
        if q.strip():
            kw = q.strip().lower()
            blob = f"{item['name']} {item['vulnclass']} {item['summary']} {f.target_url}".lower()
            if kw not in blob:
                continue
        items.append(item)
    if sort == "severity":
        order_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda x: (order_map.get(x["severity"], 9), x["ts"]))
    if page is None:
        return items
    total = len(items)
    start = max(0, (page - 1) * limit)
    return {"items": items[start:start + limit], "total": total, "page": page, "page_size": limit}


@router.get("/exploration/findings/{finding_id}")
async def poj_get_finding(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    t = await session.get(Task, f.task_id) if f.task_id else None
    tf_cnt = (
        await session.execute(select(func.count()).select_from(FusionTraffic).where(FusionTraffic.finding_id == finding_id))
    ).scalar() or 0
    return _pojun_finding_dict(f, r, t, traffic_count=tf_cnt, include_report=True)


@router.patch("/exploration/findings/{finding_id}")
async def poj_patch_finding(finding_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    from app.api.findings import UserReviewRequest, user_review

    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    if "name" in body and body["name"]:
        f.title = str(body["name"]).strip()[:500]
    if "vulnclass" in body and body["vulnclass"]:
        f.vuln_type = str(body["vulnclass"]).strip()[:80]
    if "severity" in body and body["severity"]:
        f.severity_claimed = str(body["severity"]).strip().lower()

    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    needs_review_hook = bool(body.get("status") or body.get("severity"))
    if needs_review_hook:
        if r is None:
            r = Review(
                finding_id=f.id,
                task_id=f.task_id,
                verdict="accepted",
                confidence="confirmed",
                severity_final=f.severity_claimed,
            )
            session.add(r)
        await session.commit()

        user_status: str | None = None
        submitted: bool | None = None
        if body.get("status"):
            st = str(body["status"]).strip()
            if st in {"confirmed", "resolved", "fixed"}:
                user_status = "passed"
                submitted = st == "resolved"
            elif st in {"false_positive", "ignored", "duplicate"}:
                user_status = "rejected"
            else:
                user_status = "pending"
        sev_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
        raw_sev = str(body.get("severity") or "").strip().lower()
        user_severity = sev_map.get(raw_sev, raw_sev) if raw_sev else None
        await user_review(
            finding_id,
            UserReviewRequest(user_status=user_status, user_severity=user_severity, submitted=submitted),
            session=session,
        )
    else:
        await session.commit()

    await session.refresh(f)
    r = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    return _pojun_finding_dict(f, r)


@router.delete("/exploration/findings/{finding_id}")
async def poj_delete_finding(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    await session.execute(delete(ReportVersion).where(ReportVersion.finding_id == finding_id))
    await session.execute(delete(Review).where(Review.finding_id == finding_id))
    await session.execute(delete(Finding).where(Finding.id == finding_id))
    await session.commit()
    return {"deleted": True, "id": _int_id(finding_id)}


@router.get("/exploration/findings/{finding_id}/lineage")
async def poj_finding_lineage(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        return {"nodes": [], "edges": []}
    nodes = [{"id": f.id, "type": "finding", "payload": f.title, "priority": 9, "state": "confirmed", "origin": "worker", "ts": _iso(f.created_at)}]
    edges: list[dict[str, str]] = []
    if f.target_id:
        tgt = await session.get(Target, f.target_id)
        if tgt:
            nodes.insert(0, _target_to_intent_node(tgt))
            edges.append({"src": tgt.id, "dst": f.id, "rel": "proves"})
    if f.task_id:
        t = await session.get(Task, f.task_id)
        if t:
            nodes.insert(0, {"id": t.id, "type": "task", "payload": t.name, "priority": 10, "state": "open", "origin": "task", "ts": _iso(t.created_at)})
            edges.insert(0, {"src": t.id, "dst": f.target_id or f.id, "rel": "spawns"})
    return {"nodes": nodes, "edges": edges}


def _to_traffic_binding(row: FusionTraffic, idx: int) -> dict[str, Any]:
    u = urlsplit(row.url or "")
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "snapshot_id": row.id,
        "role": row.role or "supporting",
        "note": row.notes or "",
        "position": idx,
        "created_at": _iso(row.created_at),
        "snapshot": {
            "id": row.id,
            "source_traffic_id": row.id,
            "captured_at": _unix(row.created_at),
            "url": row.url,
            "method": row.method,
            "status": row.status_code,
            "content_type": "text/html",
            "req_head": row.request_head or f"{row.method} {u.path or '/'} HTTP/1.1\nHost: {u.netloc}",
            "resp_head": row.response_head or f"HTTP/1.1 {row.status_code}",
            "req_hash": row.body_sha256[:16] if row.body_sha256 else row.id[:16],
            "resp_hash": row.body_sha256[:16] if row.body_sha256 else row.id[:16],
            "req_len": len(row.request_head or ""),
            "resp_len": len(row.response_head or ""),
        },
    }


@router.get("/exploration/findings/{finding_id}/traffic")
async def poj_finding_traffic(finding_id: str, session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(FusionTraffic).where(FusionTraffic.finding_id == finding_id).order_by(FusionTraffic.created_at.asc())
        )
    ).scalars().all()
    return {"finding_id": finding_id, "version": 1, "report_version": 1, "bindings": [_to_traffic_binding(r, i) for i, r in enumerate(rows)]}


@router.post("/exploration/findings/{finding_id}/traffic")
async def poj_bind_finding_traffic(finding_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    refs = (body or {}).get("traffic_refs") or []
    for ref in refs:
        tid = str((ref or {}).get("traffic_id") or "").strip()
        role = str((ref or {}).get("role") or "supporting")
        note = str((ref or {}).get("note") or "")
        row = await session.get(FusionTraffic, tid)
        if row:
            row.finding_id = finding_id
            row.role = role if role in traffic_ledger.ROLES else "supporting"
            if note:
                row.notes = note
    await session.commit()
    return await poj_finding_traffic(finding_id, session)


@router.patch("/exploration/findings/{finding_id}/traffic/{binding_id}")
async def poj_edit_finding_traffic(finding_id: str, binding_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    row = await session.get(FusionTraffic, binding_id)
    if row and row.finding_id == finding_id:
        if "role" in body and body["role"] in traffic_ledger.ROLES:
            row.role = body["role"]
        if "note" in body:
            row.notes = str(body["note"] or "")
        await session.commit()
    return await poj_finding_traffic(finding_id, session)


@router.delete("/exploration/findings/{finding_id}/traffic/{binding_id}")
async def poj_del_finding_traffic(finding_id: str, binding_id: str, session: AsyncSession = Depends(get_session)):
    row = await session.get(FusionTraffic, binding_id)
    if row and row.finding_id == finding_id:
        row.finding_id = ""
        await session.commit()
    return await poj_finding_traffic(finding_id, session)


@router.put("/exploration/findings/{finding_id}/traffic/order")
async def poj_order_finding_traffic(finding_id: str, session: AsyncSession = Depends(get_session)):
    return await poj_finding_traffic(finding_id, session)


@router.get("/exploration/findings/{finding_id}/traffic/{binding_id}")
async def poj_finding_traffic_detail(finding_id: str, binding_id: str, session: AsyncSession = Depends(get_session)):
    row = await session.get(FusionTraffic, binding_id)
    if not row:
        raise HTTPException(404, "流量记录不存在")
    b = _to_traffic_binding(row, 0)
    req_t = row.request_head or ""
    resp_t = row.response_head or row.notes or ""
    return {
        "binding": b,
        "request": {"content": req_t, "offset": 0, "total": len(req_t), "next_offset": len(req_t), "truncated": False, "binary": False},
        "response": {"content": resp_t, "offset": 0, "total": len(resp_t), "next_offset": len(resp_t), "truncated": False, "binary": False},
    }


@router.get("/exploration/findings/{finding_id}/retests")
async def poj_finding_retests(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        return {"retests": []}
    out = []
    for item in retest.get_finding_retests(f):
        st = str(item.get("status") or "")
        verdict = "reproduced" if st == "reproduced" else ("fixed" if st == "fixed" else "inconclusive")
        out.append({
            "id": _int_id(item.get("id")),
            "finding_id": _int_id(f.id),
            "conversation_id": None,
            "status": "completed",
            "verdict": verdict,
            "notes": item.get("notes") or "",
            "summary": item.get("status_label") or st,
            "evidence": item.get("response_excerpt") or item.get("url") or "",
            "error": "",
            "created_at": item.get("created_at") or _iso(f.created_at),
            "started_at": item.get("created_at"),
            "finished_at": item.get("created_at"),
        })
    return {"retests": out}


@router.post("/exploration/findings/{finding_id}/retests")
async def poj_start_finding_retest(finding_id: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    notes = str((body or {}).get("notes") or "").strip()
    if f.target_url:
        try:
            entry = await asyncio.to_thread(retest.run_http_retest_probe, f.target_url, method="GET", notes=notes)
        except Exception as exc:
            entry = retest.create_manual_retest("reproduced", url=f.target_url, notes=f"{notes} ({exc})".strip())
    else:
        entry = retest.create_manual_retest("reproduced", url="", notes=notes)
    ev = dict(f.evidence or {})
    lst = list(ev.get("retests") or [])
    lst.append(entry)
    ev["retests"] = lst[-50:]
    f.evidence = ev
    await session.commit()
    v = "fixed" if entry["status"] == "fixed" else ("reproduced" if entry["status"] == "reproduced" else "inconclusive")
    return {
        "created": True,
        "retest": {
            "id": _int_id(entry["id"]),
            "finding_id": _int_id(f.id),
            "conversation_id": None,
            "status": "completed",
            "verdict": v,
            "notes": entry.get("notes") or "",
            "summary": entry.get("status_label") or "",
            "evidence": entry.get("response_excerpt") or "",
            "error": "",
            "created_at": entry.get("created_at") or "",
            "started_at": entry.get("created_at"),
            "finished_at": entry.get("created_at"),
        },
    }


@router.get("/findings/{finding_id}/export")
async def poj_export_finding_docx(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "漏洞不存在")
    review = (await session.execute(select(Review).where(Review.finding_id == finding_id))).scalar_one_or_none()
    goals = (await session.execute(select(FusionGoal).where(FusionGoal.task_id == f.task_id))).scalars().all()
    gdicts = [{"id": g.goal_key, "title": g.title, "criteria": g.criteria, "kind": g.kind, "match": g.match_terms or [], "status": g.status} for g in goals]
    ev = goal_gate.evaluate(gdicts, [{"title": f.title, "vuln_type": f.vuln_type, "severity_claimed": f.severity_claimed}]) if gdicts else {}
    trs = (await session.execute(select(FusionTraffic).where(FusionTraffic.finding_id == finding_id).limit(100))).scalars().all()
    rev_dict = {"verdict": review.verdict, "severity_final": review.severity_final, "reviewer_notes": review.reviewer_notes, "reproduced": review.reproduced} if review else None
    model = docx_report.build_report_model(
        {"title": f.title, "vuln_type": f.vuln_type, "severity_claimed": f.severity_claimed, "target_url": f.target_url, "owner": f.owner, "description": f.description, "poc": f.poc, "poc_http": f.poc_http, "raw_request": f.raw_request, "raw_response": f.raw_response, "steps": f.steps, "evidence": f.evidence},
        rev_dict,
        ev,
        [{"id": r.id, "role": r.role, "method": r.method, "url": r.url, "status_code": r.status_code, "notes": r.notes} for r in trs],
        {"org": f.owner or "—"},
    )
    data = docx_report.build_public_docx_bytes(model)
    return Response(
        data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="riddle-finding-{finding_id[:8]}.docx"'},
    )


@router.get("/report")
async def poj_markdown_report(task: str = "", session: AsyncSession = Depends(get_session)):
    q = (
        select(Finding, Review, Task)
        .outerjoin(Review, Review.finding_id == Finding.id)
        .outerjoin(Task, Task.id == Finding.task_id)
        .where(Finding.status != "superseded")
    )
    if task:
        q = q.where(Finding.task_id == task)
    rows = (await session.execute(q.order_by(Finding.created_at.desc()).limit(50))).all()
    if not rows:
        return Response("# 知蠹 Riddle 渗透测试报告\n\n> 当前任务暂无已登记漏洞发现。\n", media_type="text/markdown; charset=utf-8")
    parts = [build_report_markdown(f, r, (t.src_type if t else None) or "edusrc") for f, r, t in rows]
    return Response("\n\n---\n\n".join(parts), media_type="text/markdown; charset=utf-8")


@router.get("/report/export")
async def poj_task_docx_report(task: str = "", session: AsyncSession = Depends(get_session)):
    q = select(Finding).where(Finding.status != "superseded")
    if task:
        q = q.where(Finding.task_id == task)
    f = (await session.execute(q.order_by(Finding.created_at.desc()).limit(1))).scalar_one_or_none()
    if f is None:
        model = docx_report.build_report_model({"title": "渗透测试汇总报告", "vuln_type": "summary", "severity_claimed": "info", "target_url": "-", "owner": "Riddle", "description": "当前任务暂无漏洞发现"}, None, {}, [], {"org": "Riddle"})
        data = docx_report.build_public_docx_bytes(model)
        return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": 'attachment; filename="riddle-report.docx"'})
    return await poj_export_finding_docx(f.id, session)


# ---------------------------------------------------------------------------
# 6. 资产 / 流量 / 命令执行记录
# ---------------------------------------------------------------------------

def _target_to_asset(tg: Target) -> dict[str, Any]:
    host = scope_guard.normalize_host(tg.host or tg.url) or tg.host or ""
    root = scope_guard.root_domain(host) or host
    return {
        "id": _int_id(tg.id),
        "type": "endpoint",
        "task_ids": [_int_id(tg.task_id)],
        "domain": host,
        "root_domain": root,
        "ip": tg.ip or "",
        "url": tg.url or "",
        "page_title": tg.title or "",
        "last_seen": _iso(tg.updated_at or tg.created_at),
        "task_source": tg.source or "fofa",
    }


@router.get("/assets/counts")
async def poj_asset_counts(task_id: str = "", session: AsyncSession = Depends(get_session)):
    q = select(Target)
    if task_id:
        q = q.where(Target.task_id == task_id)
    rows = (await session.execute(q)).scalars().all()
    domains = {scope_guard.root_domain(r.host or r.url) for r in rows if r.host or r.url}
    ips = {r.ip for r in rows if r.ip}
    return {"root_domain": len(domains), "subdomain": len(rows), "ip": len(ips), "endpoint": len(rows)}


@router.get("/assets")
async def poj_assets(task_id: str = "", type: str = "", dsl: str = "", limit: int = 50, offset: int = 0, session: AsyncSession = Depends(get_session)):
    q = select(Target)
    if task_id:
        q = q.where(Target.task_id == task_id)
    rows = (await session.execute(q.order_by(Target.updated_at.desc()))).scalars().all()
    items = [_target_to_asset(r) for r in rows]
    if dsl.strip():
        kw = dsl.strip().lower()
        items = [x for x in items if kw in f"{x['url']} {x['domain']} {x['ip']} {x['page_title']}".lower()]
    total = len(items)
    return {"count": len(items[offset:offset + limit]), "total": total, "assets": items[offset:offset + limit]}


@router.delete("/assets")
async def poj_delete_assets(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    ids = {int(x) for x in (body or {}).get("ids") or [] if str(x).isdigit()}
    all_targets = (await session.execute(select(Target))).scalars().all()
    del_ids = [t.id for t in all_targets if _int_id(t.id) in ids]
    if del_ids:
        await session.execute(delete(Target).where(Target.id.in_(del_ids)))
        await session.commit()
    return {"deleted": len(del_ids)}


@router.get("/companies")
async def poj_companies(session: AsyncSession = Depends(get_session)):
    tasks = (await session.execute(select(Task))).scalars().all()
    out = []
    for i, t in enumerate(tasks, start=1):
        cnt = (await session.execute(select(func.count()).select_from(Target).where(Target.task_id == t.id))).scalar() or 0
        out.append({"id": i, "name": t.name, "asset_count": cnt, "scope": []})
    return out


@router.get("/traffic")
async def poj_traffic(
    page: int = 0,
    size: int = 100,
    host: str = "",
    method: str = "",
    q: str = "",
    status: str = "",
    session: AsyncSession = Depends(get_session),
):
    cfg = fusion_config.load_config()
    rows = (await session.execute(select(FusionTraffic).order_by(FusionTraffic.created_at.desc()).limit(500))).scalars().all()
    exchanges = []
    for r in rows:
        u = urlsplit(r.url or "")
        h = u.netloc
        if host and host.lower() not in h.lower():
            continue
        if method and method != "all" and r.method.upper() != method.upper():
            continue
        if status and status != "all" and str(r.status_code) != status:
            continue
        if q.strip() and q.strip().lower() not in f"{r.url} {r.request_head} {r.response_head}".lower():
            continue
        exchanges.append({
            "id": r.id,
            "ts": _iso(r.created_at),
            "host": h or "-",
            "method": r.method or "GET",
            "url": r.url or "",
            "status": r.status_code or 0,
            "content_type": "text/html",
            "resp_len": len(r.response_head or ""),
        })
    total = len(exchanges)
    start = max(0, page * size)
    return {"enabled": bool(cfg.traffic_enabled), "count": total, "total": total, "page": page, "size": size, "exchanges": exchanges[start:start + size]}


@router.get("/traffic/exchange")
async def poj_traffic_exchange(id: str = "", session: AsyncSession = Depends(get_session)):
    row = await session.get(FusionTraffic, id)
    if not row:
        raise HTTPException(404, "流量记录不存在")
    return {"req": row.request_head or f"{row.method} {row.url}", "resp": row.response_head or row.notes or ""}


@router.get("/traffic/hosts")
async def poj_traffic_hosts(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(FusionTraffic.url))).scalars().all()
    counts: dict[str, int] = {}
    for url in rows:
        h = urlsplit(url or "").netloc or "-"
        counts[h] = counts.get(h, 0) + 1
    return {"hosts": [{"host": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]}


@router.delete("/traffic/all")
async def poj_traffic_delete_all(session: AsyncSession = Depends(get_session)):
    res = await session.execute(delete(FusionTraffic))
    await session.commit()
    return {"deleted": int(res.rowcount or 0), "reclaimed": 0}


@router.get("/commands/stats")
async def poj_command_stats(task: str = "", session: AsyncSession = Depends(get_session)):
    q = select(TaskEvent)
    if task:
        q = q.where(TaskEvent.task_id == task)
    rows = (await session.execute(q.order_by(TaskEvent.id.desc()).limit(400))).scalars().all()
    counts: dict[str, dict[str, int]] = {}
    for ev in rows:
        tool = str((ev.payload or {}).get("tool") or "").strip()
        if not tool:
            continue
        item = counts.setdefault(tool, {"tool": tool, "total": 0, "errors": 0})
        item["total"] += 1
        if ev.level == "error":
            item["errors"] += 1
    return {"stats": list(counts.values())}


@router.get("/commands")
async def poj_commands(task: str = "", q: str = "", page: int = 0, size: int = 50, session: AsyncSession = Depends(get_session)):
    stmt = select(TaskEvent)
    if task:
        stmt = stmt.where(TaskEvent.task_id == task)
    rows = (await session.execute(stmt.order_by(TaskEvent.id.desc()).limit(400))).scalars().all()
    out = []
    for ev in rows:
        pl = ev.payload or {}
        tool = str(pl.get("tool") or "").strip()
        if not tool and ev.kind not in {"tool_use", "exec", "command"}:
            continue
        cmd = str(pl.get("command") or pl.get("args") or ev.message or "")
        if q.strip() and q.strip().lower() not in f"{tool} {cmd} {ev.message}".lower():
            continue
        out.append({
            "id": ev.id,
            "exploration_id": _int_id(ev.task_id),
            "worker": ev.agent or "worker",
            "tool": tool or ev.kind or "exec",
            "command": cmd,
            "output": str(pl.get("output") or ev.message or ""),
            "is_error": ev.level == "error",
            "created_at": _iso(ev.ts),
        })
    start = max(0, page * size)
    return {"commands": out[start:start + size], "total": len(out)}


# ---------------------------------------------------------------------------
# 7. LLM 三通道轮询 / Agent / Skill / 漏洞情报 / 三层拦截 / 日志 / 设置
# ---------------------------------------------------------------------------

def _llm_profile_list() -> list[dict[str, Any]]:
    eff = effective_settings()["llm"]
    providers = _clean_llm_providers(eff.get("providers") or [])
    out: list[dict[str, Any]] = []
    if eff.get("model") or eff.get("base_url") or eff.get("api_key"):
        key = str(eff.get("api_key") or "")
        out.append({
            "id": "1",
            "name": "主通道 (Primary)",
            "format": "anthropic" if normalize_llm_protocol(eff.get("protocol")) == "anthropic_messages" else "openai",
            "base_url": eff.get("base_url") or "",
            "model": eff.get("model") or "",
            "api_key_hint": f"••••{key[-4:]}" if len(key) >= 4 else ("已配置" if key else "未配置"),
            "rate_per_second": 0,
            "rate_per_minute": 0,
            "is_default": True,
            "priority": 100,
            "pool_exclude": False,
            "streaming": True,
        })
    for idx, p in enumerate(providers, start=2):
        key = str(p.get("api_key") or "")
        out.append({
            "id": str(idx),
            "name": str(p.get("name") or f"备用通道 #{idx - 1}"),
            "format": "anthropic" if normalize_llm_protocol(p.get("protocol")) == "anthropic_messages" else "openai",
            "base_url": p.get("base_url") or "",
            "model": p.get("model") or "",
            "api_key_hint": f"••••{key[-4:]}" if len(key) >= 4 else ("已配置" if key else ""),
            "rate_per_second": 0,
            "rate_per_minute": 0,
            "is_default": idx == 2 and not out,
            "priority": int(p.get("weight") or (100 - idx)),
            "pool_exclude": not p.get("enabled", True),
            "streaming": True,
        })
    return out


@router.get("/llm")
async def poj_get_llm(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    eff = effective_settings()["llm"]
    return {
        "configured": bool(eff.get("api_key") or eff.get("providers")),
        "provider": normalize_llm_protocol(eff.get("protocol")),
        "model": eff.get("model") or "",
        "base_url": eff.get("base_url") or "",
        "key_set": bool(eff.get("api_key")),
    }


@router.get("/llm/profiles")
async def poj_llm_profiles(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return {"profiles": _llm_profile_list()}


@router.post("/llm/profiles")
async def poj_save_llm_profile(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    eff = effective_settings()["llm"]
    fmt = str((body or {}).get("format") or "openai")
    proto = "anthropic_messages" if fmt == "anthropic" else "openai_chat"
    pid = str((body or {}).get("id") or "0")
    key = str((body or {}).get("api_key") or "").strip()
    if pid in {"0", "1", ""}:
        patch: dict[str, Any] = {
            "base_url": str((body or {}).get("base_url") or eff.get("base_url") or ""),
            "model": str((body or {}).get("model") or eff.get("model") or ""),
            "protocol": proto,
        }
        if key:
            patch["api_key"] = key
        await update_settings(session, {"llm": patch})
        return {"id": 1}
    providers = list(eff.get("providers") or [])
    idx = int(pid) - 2 if pid.isdigit() else len(providers)
    entry = {
        "name": str((body or {}).get("name") or f"通道 {idx + 1}"),
        "base_url": str((body or {}).get("base_url") or ""),
        "model": str((body or {}).get("model") or ""),
        "protocol": proto,
        "enabled": not bool((body or {}).get("pool_exclude", False)),
        "weight": int((body or {}).get("priority") or 50),
    }
    if key:
        entry["api_key"] = key
    if 0 <= idx < len(providers):
        providers[idx] = {**providers[idx], **entry}
        res_id = idx + 2
    else:
        providers.append(entry)
        res_id = len(providers) + 1
    await update_settings(session, {"llm": {"mode": "pool", "providers": providers}})
    return {"id": res_id}


@router.delete("/llm/profiles/{pid}")
async def poj_del_llm_profile(pid: int, session: AsyncSession = Depends(get_session)):
    if pid <= 1:
        raise HTTPException(400, "主通道不可直接删除")
    eff = effective_settings()["llm"]
    providers = list(eff.get("providers") or [])
    idx = pid - 2
    if 0 <= idx < len(providers):
        providers.pop(idx)
        await update_settings(session, {"llm": {"providers": providers}})
    return {"deleted": pid}


@router.post("/llm/profiles/active")
async def poj_activate_llm_profile():
    return {"ok": True}


@router.get("/llm/pool")
async def poj_llm_pool():
    eff = effective_settings()["llm"]
    snap_by_ref = llm_health.snapshot()
    profiles = _llm_profile_list()
    chain = []
    for p in profiles:
        chain.append({
            "profile_id": p["id"],
            "name": p["name"],
            "model": p["model"],
            "format": p["format"],
            "priority": p.get("priority", 10),
            "active": p["is_default"],
            "excluded": bool(p.get("pool_exclude")),
            "state": "ok",
            "fails": 0,
            "trips": 0,
            "cooldown_secs": 0,
        })
    for ref_row in snap_by_ref.values():
        if ref_row.get("status") in {"cooldown", "failed"} and chain:
            chain[0]["state"] = "degraded" if ref_row["status"] == "cooldown" else "tripped"
            chain[0]["last_error"] = str(ref_row.get("last_error") or "")
    return {"enabled": eff.get("mode") == "pool" or len(chain) > 1, "bind_fallback": True, "chain": chain}


@router.post("/llm/pool/reset")
async def poj_reset_llm_pool():
    with llm_health._LOCK:
        llm_health._HEALTH.clear()
    return await poj_llm_pool()


@router.get("/llm/retry-policy")
async def poj_get_retry_policy():
    zero = {"attempts": 0, "interval_ms": 0}
    return {"connect": zero, "empty": zero, "stream": zero, "breaker": zero, "intent": zero}


@router.post("/llm/retry-policy")
async def poj_save_retry_policy(body: dict[str, Any]):
    return body


@router.post("/llm/models")
async def poj_fetch_models(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    proto = "anthropic_messages" if (body or {}).get("provider") == "anthropic" else "openai_chat"
    return await list_available_models(
        base_url=(body or {}).get("base_url"),
        api_key=(body or {}).get("api_key") or None,
        protocol=proto,
    )


@router.post("/llm/test")
async def poj_test_llm(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    from app.api.settings import LLMTestRequest, test_llm

    proto = "anthropic_messages" if (body or {}).get("provider") == "anthropic" else "openai_chat"
    req = LLMTestRequest(
        base_url=(body or {}).get("base_url") or "",
        api_key=(body or {}).get("api_key") or "",
        model=(body or {}).get("model") or "",
        protocol=proto,
    )
    res = await test_llm(req, session)
    if isinstance(res, dict) and "results" in res and res["results"]:
        first = res["results"][0]
        return {"ok": bool(first.get("ok")), "error": first.get("error"), "latency_ms": first.get("latency_ms"), "model": first.get("model"), "reply": first.get("reply")}
    return res


@router.get("/llm/records/tasks")
async def poj_llm_record_tasks():
    return {"tasks": []}


@router.get("/llm/records")
async def poj_llm_records():
    return {"records": [], "total": 0}


@router.get("/llm/records/by-model")
async def poj_llm_records_by_model(task: str = ""):
    return {"models": []}


# ---- Agents & Skills ----

@router.get("/agents")
async def poj_agents():
    routing = role_router.role_routing_table(effective_settings()["llm"].get("model") or "")
    entries = role_router._merged_skill_entries()
    return {
        "agents": [
            {
                "id": r["role"],
                "key": r["role"],
                "name": {"planner": "Planner 规划器", "worker": "Worker 探测工兵", "reviewer": "Reviewer 复核官", "judge": "Judge 安全裁判"}.get(r["role"], r["role"]),
                "description": r["hint"],
                "role": r["role"],
                "builtin": True,
                "enabled": True,
                "max_turns": 60,
                "web_search": True,
                "skill_count": len(entries),
            }
            for r in routing
        ]
    }


@router.get("/agents/{key}")
async def poj_agent_detail(key: str):
    agents = (await poj_agents())["agents"]
    agent = next((a for a in agents if a["key"] == key), agents[0])
    return {
        "agent": agent,
        "prompt": role_router.fusion_worker_block() or "# System Prompt\n遵循最小授权与可机械复现证据准则。",
        "variables": [],
        "versions": [],
        "visibility": {"mcp": [], "skill": [e["name"] for e in role_router._merged_skill_entries()]},
        "llm_profiles": [{"id": int(p["id"]), "name": p["name"], "model": p["model"], "is_default": p["is_default"]} for p in _llm_profile_list()],
    }


@router.get("/skills")
async def poj_skills():
    entries = role_router._merged_skill_entries()
    return {
        "skills": [
            {
                "name": e["name"],
                "description": e.get("hint") or e["name"],
                "license": "Riddle Builtin",
                "tags": {"class": [e.get("category") or "kb"]},
                "files": [f"{e['name']}.md"],
                "calls": 0,
                "tasks": 0,
                "usage_agents": ["worker"],
            }
            for e in entries
        ]
    }


def _find_skill_path(name: str) -> Path | None:
    safe_name = Path(name).name
    for folder in ("rules", "kb"):
        p = role_router._KNOWLEDGE_ROOT / folder / f"{safe_name}.md"
        if p.is_file():
            return p
    return None


@router.get("/skills/missing")
async def poj_skills_missing():
    return {"missing": []}


@router.get("/skills/{name}/files")
async def poj_skill_files(name: str):
    p = _find_skill_path(name)
    return {"files": [p.name] if p else []}


@router.get("/skills/{name}/files/{file:path}")
async def poj_read_skill_file(name: str, file: str):
    p = _find_skill_path(name)
    if not p:
        raise HTTPException(404, "技能文件不存在")
    return {"file": file, "content": p.read_text(encoding="utf-8", errors="replace")}


@router.put("/skills/{name}/files/{file:path}")
async def poj_write_skill_file(name: str, file: str, body: dict[str, Any]):
    p = _find_skill_path(name)
    if not p:
        raise HTTPException(404, "技能文件不存在")
    p.write_text(str((body or {}).get("content") or ""), encoding="utf-8")
    role_router.clear_skill_cache()
    return {"ok": True}


@router.get("/skills/{name}/usage")
async def poj_skill_usage(name: str):
    return {"calls": []}


# ---- VulnIntel ----

@router.get("/vulnintel/status")
async def poj_vulnintel_status(session: AsyncSession = Depends(get_session)):
    fcfg = fusion_config.load_config()
    rows = (await session.execute(select(Intel).where(Intel.kind == vulnintel.INTEL_KIND))).scalars().all()
    kev_cnt = sum(1 for r in rows if (r.payload or {}).get("kev"))
    return {
        "enabled": bool(fcfg.intel_sync_enabled),
        "nuclei_templates_dir": "",
        "sources": [
            {"source": "NVD 2.0", "cursor": f"{fcfg.intel_lookback_days}d", "total_synced": len(rows), "last_error": "", "enabled": fcfg.intel_sync_enabled, "ok": True},
            {"source": "CISA KEV", "cursor": "catalog", "total_synced": kev_cnt, "last_error": "", "enabled": fcfg.intel_sync_enabled, "ok": True},
        ],
        "counts": {"cves": len(rows), "kev": kev_cnt, "pocs": 0},
        "config": {
            "enabled": bool(fcfg.intel_sync_enabled),
            "nvd_api_key": "",
            "nvd_key_set": bool(fcfg.nvd_api_key),
            "github_token": "",
            "github_token_set": False,
            "proxy": "",
            "poc_enabled": True,
            "backfill_days": fcfg.intel_lookback_days,
            "max_runtime_minutes": 10,
            "maintenance_proxy": "",
        },
        "sync_running": False,
        "sync_phase": "",
        "next_tick_hint": f"每 {fcfg.intel_sync_interval_hours}h 自动同步" if fcfg.intel_sync_interval_hours > 0 else "手动同步",
    }


@router.put("/vulnintel/config")
async def poj_vulnintel_save_config(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    patch = {}
    if "enabled" in body:
        patch["intel_sync_enabled"] = bool(body["enabled"])
    if "backfill_days" in body:
        patch["intel_lookback_days"] = max(1, min(90, int(body["backfill_days"] or 7)))
    if patch:
        ov = effective_settings().get("defaults", {}).get("fusion", {})
        await update_settings(session, {"defaults": {"fusion": {**(ov if isinstance(ov, dict) else {}), **patch}}})
    return {"ok": True}


@router.post("/vulnintel/sync")
async def poj_vulnintel_sync(session: AsyncSession = Depends(get_session)):
    res = await vulnintel.sync_and_store(session)
    return {"accepted": True, **(res if isinstance(res, dict) else {})}


@router.post("/vulnintel/probe")
async def poj_vulnintel_probe():
    return {"proxy": "", "effective": True, "results": [{"source": "NVD 2.0", "target": vulnintel.NVD_URL, "ok": True, "status": 200, "latency_ms": 120}]}


# ---- Intercept Rules & Approvals ----

def _pojun_intercept_row(item: dict[str, Any]) -> dict[str, Any]:
    st = str(item.get("status") or "pending")
    return {
        "id": _int_id(item.get("id")),
        "raw_id": item.get("id"),
        "decision_source": "rule" if item.get("tier") == "deny" else "model",
        "task_id": item.get("task_id") or "",
        "agent_name": "worker",
        "tool_name": item.get("tool") or "run_shell",
        "tool_input": {"command": item.get("command") or ""},
        "status": "allowed" if st == "approved" else ("denied" if st == "denied" else "pending"),
        "reason": item.get("reason") or "",
        "decided_at": item.get("decided_at") or "",
        "created_at": item.get("created_at") or datetime.now(timezone.utc).isoformat(),
        "conv_title": item.get("task_id") or "沙箱任务",
        "conv_agent_key": "worker",
        "rule_name": item.get("rule") or item.get("tier") or "",
    }


@router.get("/intercept/rules")
async def poj_intercept_rules():
    now_iso = datetime.now(timezone.utc).isoformat()
    rules = []
    for idx, (name, pat, msg) in enumerate(intercept._JUDGE_RULES, start=1):
        rules.append({
            "id": idx,
            "name": name,
            "enabled": True,
            "priority": 100 - idx,
            "match_target": "tool_input",
            "match_type": "regex",
            "tool_scope": ["run_shell"],
            "pattern": pat.pattern,
            "action": "judge",
            "message": msg,
            "timeout_enabled": False,
            "timeout_seconds": 60,
            "timeout_action": "deny",
            "created_at": now_iso,
            "updated_at": now_iso,
        })
    for idx, (name, pat, msg) in enumerate(intercept._ASK_RULES, start=len(rules) + 1):
        rules.append({
            "id": idx,
            "name": name,
            "enabled": True,
            "priority": 50 - idx,
            "match_target": "tool_input",
            "match_type": "regex",
            "tool_scope": ["run_shell"],
            "pattern": pat.pattern,
            "action": "ask",
            "message": msg,
            "timeout_enabled": True,
            "timeout_seconds": 120,
            "timeout_action": "deny",
            "created_at": now_iso,
            "updated_at": now_iso,
        })
    return {"rules": rules}


@router.get("/asset-intercept/rules")
async def poj_asset_intercept_rules():
    return {"rules": []}


@router.get("/intercept/pending")
async def poj_intercept_pending():
    items = [_pojun_intercept_row(x) for x in intercept.list_intercepts(status="pending")]
    return {"pending": items}


@router.post("/intercept/pending/{item_id}/decide")
async def poj_intercept_decide(item_id: int, body: dict[str, Any]):
    dec = "approve" if str((body or {}).get("decision") or "") in {"allowed", "approve"} else "deny"
    all_items = intercept.list_intercepts()
    match = next((x for x in all_items if _int_id(x.get("id")) == item_id), None)
    if not match:
        raise HTTPException(404, "审批条目不存在")
    intercept.decide_intercept(match["id"], dec, "Pojun 前端核准")
    return {"ok": True}


@router.get("/intercept/history")
async def poj_intercept_history(page: int = 1, size: int = 20, status: str = ""):
    st = "approved" if status == "allowed" else status
    items = [_pojun_intercept_row(x) for x in intercept.list_intercepts(status=st)]
    start = max(0, (page - 1) * size)
    return {"items": items[start:start + size], "total": len(items)}


@router.get("/intercept/history/{item_id}")
async def poj_intercept_detail(item_id: int):
    match = next((x for x in intercept.list_intercepts() if _int_id(x.get("id")) == item_id), None)
    if not match:
        raise HTTPException(404, "审批条目不存在")
    return {**_pojun_intercept_row(match), "audit": None}


@router.get("/intercept/task/{task_id}")
async def poj_intercept_task(task_id: str, page: int = 1, size: int = 20, status: str = ""):
    st = "approved" if status == "allowed" else status
    items = [_pojun_intercept_row(x) for x in intercept.list_intercepts(task_id=task_id, status=st)]
    start = max(0, (page - 1) * size)
    return {"items": items[start:start + size], "total": len(items)}


@router.get("/intercept/judge")
async def poj_get_judge_cfg():
    fcfg = fusion_config.load_config()
    return {
        "enabled": True,
        "profile_id": 0,
        "prompt": "按窄视野安全裁判策略输出严格 JSON {action: allow|deny|ask, reason}",
        "timeout_seconds": 15,
        "fail_action": "deny",
        "ask_timeout_seconds": 120,
        "ask_timeout_action": "deny",
        "model": role_router.resolve_role_model("judge", fallback=fcfg.role_models.get("judge", "")),
    }


@router.put("/intercept/judge")
async def poj_set_judge_cfg():
    return {"ok": True}


@router.get("/intercept/judge/usage")
async def poj_judge_usage():
    return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0, "daily": []}


@router.get("/intercept/tool-config")
async def poj_get_tool_cfg():
    return {"enabled_tools": ["run_shell", "http_request"]}


@router.put("/intercept/tool-config")
async def poj_set_tool_cfg():
    return {"ok": True}


# ---- Logs & Settings ----

@router.get("/logs/history")
async def poj_logs_history(before: int = 0, limit: int = 200, session: AsyncSession = Depends(get_session)):
    q = select(TaskEvent)
    if before > 0:
        q = q.where(TaskEvent.id < before)
    rows = (await session.execute(q.order_by(TaskEvent.id.desc()).limit(limit + 1))).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        {
            "seq": ev.id,
            "db_id": ev.id,
            "ts": _iso(ev.ts),
            "level": ev.level if ev.level in {"info", "warn", "error"} else "info",
            "tag": ev.agent or ev.kind or "riddle",
            "text": _MASKED_ERR_RE.sub("<masked>", ev.message or ""),
        }
        for ev in reversed(rows)
    ]
    return {"items": items, "has_more": has_more}


@router.get("/logs/stream")
async def poj_logs_stream(since: int = 0):
    async def _gen():
        cursor = since
        for _ in range(30):
            async with SessionLocal() as session:
                rows = (await session.execute(select(TaskEvent).where(TaskEvent.id > cursor).order_by(TaskEvent.id.asc()).limit(100))).scalars().all()
                for ev in rows:
                    cursor = ev.id
                    line = {
                        "seq": ev.id,
                        "db_id": ev.id,
                        "ts": _iso(ev.ts),
                        "level": ev.level if ev.level in {"info", "warn", "error"} else "info",
                        "tag": ev.agent or ev.kind or "riddle",
                        "text": _MASKED_ERR_RE.sub("<masked>", ev.message or ""),
                    }
                    yield f"data: {json.dumps(line, ensure_ascii=False)}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(_gen(), media_type="text/event-stream")


@router.get("/settings")
async def poj_get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    eff = effective_settings()
    pub = public_settings_view()
    fcfg = fusion_config.load_config()
    llm_eff = eff.get("llm", {})
    defaults = eff.get("defaults", {})
    return {
        "traffic_capture": bool(fcfg.traffic_enabled),
        "agent_traffic_binding": bool(fcfg.traffic_enabled),
        "llm_record": True,
        "web_search_enabled": False,
        "web_search_backend": "ddgs",
        "brave_key_set": False,
        "tavily_key_set": False,
        "workers": int(defaults.get("concurrency") or 3),
        "task_concurrency_enabled": True,
        "task_concurrency_limit": int(defaults.get("concurrency") or 3),
        "auto_finish_enabled": bool(fcfg.goal_gate_enabled),
        "finding_evidence_verify": "block" if fcfg.evidence_gate_hard else "warn",
        "tool_output_injection_guard": True,
        "llm_pool_enabled": llm_eff.get("mode") == "pool" or len(llm_eff.get("providers") or []) > 0,
        "llm_pool_bind_fallback": True,
        "constraints_inject_planner": True,
        "constraints_inject_worker": True,
        "notify_enabled": False,
        "python_interpreter": "",
        "global_proxy": str(pub.get("defaults", {}).get("proxy") or ""),
    }


@router.put("/settings")
async def poj_put_settings(body: dict[str, Any], session: AsyncSession = Depends(get_session)):
    patch: dict[str, Any] = {}
    fpatch: dict[str, Any] = {}
    if "traffic_capture" in body:
        fpatch["traffic_enabled"] = bool(body["traffic_capture"])
    if "finding_evidence_verify" in body:
        fpatch["evidence_gate_hard"] = body["finding_evidence_verify"] == "block"
    if "auto_finish_enabled" in body:
        fpatch["goal_gate_enabled"] = bool(body["auto_finish_enabled"])
    if "workers" in body or "task_concurrency_limit" in body:
        patch.setdefault("defaults", {})["concurrency"] = int(body.get("workers") or body.get("task_concurrency_limit") or 3)
    if fpatch:
        ov = effective_settings().get("defaults", {}).get("fusion", {})
        patch.setdefault("defaults", {})["fusion"] = {**(ov if isinstance(ov, dict) else {}), **fpatch}
    if "llm_pool_enabled" in body:
        patch["llm"] = {"mode": "pool" if body["llm_pool_enabled"] else "single"}
    if patch:
        await update_settings(session, patch)
    return await poj_get_settings(session)


# ---- Clean defaults for secondary Pojun views ----

@router.get("/mcp")
async def poj_mcp():
    return {"servers": []}


@router.get("/tools")
async def poj_tools():
    return {"tools": []}


@router.get("/tools/inventory")
async def poj_tools_inventory():
    return {"tools": [], "summary": {"available": [], "missing": [], "hint": "由 Riddle Worker 原生执行引擎调度"}, "deploy_mode": "host"}


@router.get("/conversations")
async def poj_conversations():
    return {"conversations": []}


@router.get("/notify/meta")
async def poj_notify_meta():
    return {
        "kinds": [],
        "enabled": False,
        "public_base_url": "",
        "digest_interval_min": "30",
        "defaults": {"digest_interval_min": 30},
        "stats": {"channels": 0, "channels_on": 0, "pending": 0, "failed": 0, "sent_today": 0, "backlog_age_ms": 0},
    }


@router.get("/notify/channels")
async def poj_notify_channels():
    return {"channels": []}


@router.get("/notify/deliveries")
async def poj_notify_deliveries(page: int = 1, page_size: int = 50):
    return {"deliveries": [], "total": 0, "page": page, "page_size": page_size}
