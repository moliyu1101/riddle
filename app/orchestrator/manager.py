"""多任务管理器：每任务一个 TaskRunner，控制面入口（启动/停止/指令）。"""
from __future__ import annotations

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import threading
import traceback
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import dedup
from app.blackboard import Blackboard
from app.tools import escalation_guard
from app.agents import collector
from app.agents import intel as intel_lib
from app.agents import playbook_router
from app.agents import prefilter
from app.agents import site_collab
from app.agents import target_cluster
from app.agents.business_profiler import profile_business, render_business_block
from app.agents.biz_test_template import render_biz_test_block
from app.agents.diff_score import diff_strategy_block
from app.agents.state_machine import render_state_machine_block
from app.agents.throttle import compute_effective_cap, same_org_ratio
from app.agents.deepen import deepen_cap_for  # 任务级深挖上限（人工+AI+lead 合计，防死循环）
from app.agents.prompts import is_enterprise_src, should_escalate
from app.agents.reviewer import Reviewer
from app.agents.worker import Worker
from app.agent_runtime import (
    AGENT_EXECUTOR, COLLECTOR_IO_EXECUTOR, WORKER_MAX_CONCURRENCY,
    QUEUE_LIVENESS_BATCH_SIZE, QUEUE_LIVENESS_CONCURRENCY,
    agent_semaphore, shutdown_agent_executor,
)
from app.db.models import CST, Finding, Killsweep, Review, Target, Task, TaskEvent
from app.db.session import SessionLocal
from app.events import bus
from app.maintenance.cleanup import TRACE_FINE_KINDS, prune_target_traces
from app.llm.client import LLMClient
from app.settings_service import (
    llm_client_for_task,
    resolve_engine_config,
    resolve_engine_name,
    resolve_llm_runtime_mode,
    resolve_worker_prompt_version,
)
from app.schemas import Finding as FindingSchema
from app.schemas import Verdict


from app.orchestrator._common import *  # noqa: F401,F403
from app.orchestrator.runner import TaskRunner


class OrchestratorManager:
    """管理所有任务的 runner。FastAPI lifespan 启动时恢复 running 任务。"""

    def __init__(self) -> None:
        self._runners: dict[str, TaskRunner] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def get_runner(self, task_id: str) -> "TaskRunner | None":
        return self._runners.get(task_id)

    async def skip_target(self, task_id: str, target_id: str,
                          reason: str = "用户手动删除该目标") -> dict:
        """删除/跳过某任务下的一个目标。任务在运行→交给 runner（会取消在跑 worker）；
        任务已暂停/停止（无活跃 runner）→ 直接改 DB 状态即可（无 worker 需取消）。"""
        runner = self.get_runner(task_id)
        if runner is not None:
            return await runner.skip_target(target_id, reason)
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt or tgt.task_id != task_id:
                return {"ok": False, "error": "目标不存在或不属于该任务"}
            host = tgt.host or tgt.url or target_id
            tgt.status = "skipped"
            tgt.verdict = "user_skipped"
            tgt.assigned_worker = ""
            tgt.heartbeat_at = None
            tgt.dead_reason = (reason or "用户手动删除")[:300]
            tgt.last_error = ""
            await session.commit()
        return {"ok": True, "target_id": target_id, "host": host}

    def inject_directive(self, task_id: str, target_id: str, directive: str) -> dict:
        runner = self.get_runner(task_id)
        if runner is None:
            return {"ok": False, "error": "任务未在运行"}
        return runner.inject_directive(target_id, directive)

    def cancel_escalation(self, task_id: str, finding_id: str,
                          reason: str = "用户取消扩大危害") -> dict:
        runner = self.get_runner(task_id)
        if runner is None:
            return {"ok": False, "error": "任务未在运行"}
        return runner.cancel_escalation(finding_id, reason)

    def diagnostic_snapshot(self) -> dict:
        return {
            "runner_count": len(self._runners),
            "task_count": len(self._tasks),
            "runners": {
                task_id: runner.diagnostic_snapshot()
                for task_id, runner in self._runners.items()
            },
            "tasks": {
                task_id: {
                    "done": task.done(),
                    "cancelled": task.cancelled(),
                    "coro": getattr(task.get_coro(), "__qualname__", repr(task.get_coro())),
                }
                for task_id, task in self._tasks.items()
            },
        }

    async def trigger_killsweep(self, task_id: str, finding_id: str) -> bool:
        """触发通杀 Hunter（复审通过或通杀列手动重启）。

        任务即使当前不在 running，也允许做一次离线通杀分析；这里创建轻量 runner
        只承载该后台任务，不自动启动主挖掘循环。
        """
        runner = self._runners.get(task_id)
        if not runner:
            runner = TaskRunner(task_id)
            # 离线通杀也挂到 manager，后续 stop/pause 才能统一取消它。
            self._runners[task_id] = runner
        return await runner.trigger_killsweep(task_id, finding_id)

    async def ensure_running(self, task_id: str) -> None:
        existing_task = self._tasks.get(task_id)
        if task_id in self._runners and existing_task and not existing_task.done():
            return
        if existing_task and existing_task.done():
            self._tasks.pop(task_id, None)
        runner = self._runners.get(task_id)
        if not runner or runner._stop.is_set():
            runner = TaskRunner(task_id)
            self._runners[task_id] = runner
        self._runners[task_id] = runner
        self._tasks[task_id] = asyncio.create_task(runner.run_forever())

    async def stop(self, task_id: str) -> None:
        runner = self._runners.pop(task_id, None)
        if runner:
            await runner.stop()
        t = self._tasks.pop(task_id, None)
        if t:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t

    async def pause(self, task_id: str) -> None:
        runner = self._runners.get(task_id)
        if runner:
            await runner.pause()

    async def restore_on_startup(self) -> None:
        """重启恢复：把 running/idle 的任务重新拉起。"""
        async with SessionLocal() as session:
            rows = await session.execute(select(Task).where(Task.status.in_(["running", "idle"])))
            for task in rows.scalars().all():
                await self.ensure_running(task.id)

    async def pause_on_startup(self) -> None:
        """安全启动模式：只恢复 Web/API，把历史运行任务暂停并回收半路目标。"""
        async with SessionLocal() as session:
            rows = (await session.execute(
                select(Task).where(Task.status.in_(["running", "idle"]))
            )).scalars().all()
            for task in rows:
                runner = TaskRunner(task.id)
                await runner.recover(session)
                task.status = "paused"
                await session.commit()
                await runner._log(
                    session, "orchestrator", "safe_startup_pause",
                    "安全启动模式：容器启动未自动恢复任务，已暂停历史 running/idle 任务",
                    level="warn",
                )

    async def shutdown(self) -> None:
        """应用退出时统一取消 runner，关闭线程池，避免子线程/子进程拖住 uvicorn。"""
        task_ids = list(self._runners.keys())
        await asyncio.gather(*(self.stop(task_id) for task_id in task_ids), return_exceptions=True)
        shutdown_agent_executor()



manager = OrchestratorManager()
