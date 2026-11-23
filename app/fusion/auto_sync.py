"""融合层全自动闭环联动：漏洞入库/过审时自动归集绑定实证流量并重评目标闸门。

设计原则：旁路、幂等、失败静默降级，绝不阻塞 Worker / Reviewer 主流水线。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, FusionGoal, FusionTraffic
from app.fusion import config as fusion_config
from app.fusion import goal_gate, traffic_ledger


def _host_of(url: str) -> str:
    try:
        return (urlparse(url or "").hostname or "").lower()
    except Exception:
        return ""


def _candidate_traffic_dirs(work_dir: str = "") -> list[str]:
    dirs: list[str] = []
    if work_dir and Path(work_dir).exists():
        dirs.append(work_dir)
    roots = [os.getenv("WORKER_WORK_ROOT", ""), str(Path.cwd() / "work"), str(Path.cwd() / "data")]
    for raw in roots:
        if not raw:
            continue
        p = Path(raw)
        if not p.exists():
            continue
        try:
            for f in list(p.glob("**/" + traffic_ledger.JSONL_NAME))[:20]:
                dirs.append(str(f.parent))
        except OSError:
            continue
    return sorted(set(dirs))[:20]


async def auto_bind_traffic_for_finding(
    session: AsyncSession,
    task_id: str,
    finding_id: str,
    target_url: str,
    *,
    work_dir: str = "",
) -> dict[str, Any]:
    """扫描工作区 fusion_traffic.jsonl，将同主机流量幂等入库并自动绑定至该漏洞。"""
    target_host = _host_of(target_url)
    if not target_host:
        return {"imported": 0, "bound": 0}

    rows: list[dict[str, Any]] = []
    for d in _candidate_traffic_dirs(work_dir):
        rows.extend(traffic_ledger.read_jsonl(d))
    if not rows:
        return {"imported": 0, "bound": 0}

    matched_rows = [r for r in rows if _host_of(str(r.get("url") or "")) == target_host]
    if not matched_rows:
        return {"imported": 0, "bound": 0}

    built = traffic_ledger.build_db_rows(matched_rows, task_id)
    imported = 0
    bound = 0
    for row in built:
        existing = (
            await session.execute(
                select(FusionTraffic).where(
                    FusionTraffic.task_id == task_id,
                    FusionTraffic.body_sha256 == row["body_sha256"],
                    FusionTraffic.url == row["url"],
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row["finding_id"] = finding_id
            if row.get("role") not in traffic_ledger.ROLES:
                row["role"] = "proof"
            session.add(FusionTraffic(**row))
            imported += 1
            bound += 1
        elif not existing.finding_id:
            existing.finding_id = finding_id
            bound += 1
    return {"imported": imported, "bound": bound}


async def auto_evaluate_task_goals(session: AsyncSession, task_id: str) -> dict[str, Any]:
    """用任务最新漏洞重新评估 FusionGoal 并回写达成状态。"""
    goal_rows = (
        await session.execute(select(FusionGoal).where(FusionGoal.task_id == task_id))
    ).scalars().all()
    if not goal_rows:
        return {"configured": False, "updated": 0}

    findings = (
        await session.execute(
            select(Finding).where(Finding.task_id == task_id, Finding.status != "superseded")
        )
    ).scalars().all()

    goals_payload = [
        {
            "id": g.goal_key,
            "title": g.title,
            "criteria": g.criteria,
            "kind": g.kind,
            "match": g.match_terms or [],
            "status": g.status,
            "evidence_ref": g.evidence_ref,
        }
        for g in goal_rows
    ]
    finding_payload = [
        {
            "id": f.id,
            "title": f.title,
            "vuln_type": f.vuln_type,
            "severity_claimed": f.severity_claimed,
            "target_url": f.target_url,
            "description": f.description,
            "poc": f.poc,
            "evidence": f.evidence or {},
        }
        for f in findings
    ]
    result = goal_gate.evaluate(goals_payload, finding_payload)
    met_keys = {str(item.get("id") or "") for item in (result.get("met") or [])}
    latest_fid = findings[-1].id if findings else ""
    updated = 0
    for row in goal_rows:
        if row.goal_key in met_keys:
            new_status = "met"
            new_ref = row.evidence_ref or latest_fid
        else:
            new_status = row.status or "open"
            new_ref = row.evidence_ref or ""
        if row.status != new_status or row.evidence_ref != new_ref:
            row.status = new_status
            row.evidence_ref = new_ref
            updated += 1
    return {
        "configured": True,
        "updated": updated,
        "met_count": int(result.get("met_count") or 0),
        "terminal_state": result.get("terminal_state", "incomplete"),
    }


async def on_finding_reviewed(
    session: AsyncSession,
    task_id: str,
    finding_id: str,
    target_url: str,
    *,
    work_dir: str = "",
) -> dict[str, Any]:
    """AI 初审通过后自动联动实证流量绑定 + 目标闸门重评。"""
    cfg = fusion_config.load_config()
    traffic_res = {"imported": 0, "bound": 0}
    goal_res = {"configured": False, "updated": 0}
    if cfg.traffic_enabled or work_dir:
        traffic_res = await auto_bind_traffic_for_finding(
            session, task_id, finding_id, target_url, work_dir=work_dir
        )
    if cfg.goal_gate_enabled:
        goal_res = await auto_evaluate_task_goals(session, task_id)
    return {"traffic": traffic_res, "goals": goal_res}
