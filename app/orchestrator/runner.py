"""TaskRunner 组合类：仅负责状态容器初始化，行为分散在各职责 Mixin。"""
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
from app.orchestrator.dispatch import DispatchMixin
from app.orchestrator.killsweep import KillsweepMixin
from app.orchestrator.persistence import PersistenceMixin
from app.orchestrator.review import ReviewMixin
from app.orchestrator.workers import WorkersMixin


class TaskRunner(DispatchMixin, WorkersMixin, ReviewMixin, KillsweepMixin, PersistenceMixin):
    def __init__(self, task_id: str):
        self.task_id = task_id
        self._stop = asyncio.Event()
        self._active_workers: dict[str, asyncio.Task] = {}
        self._worker_cancel_events: dict[str, threading.Event] = {}
        self._cancelled_targets: set[str] = set()
        self._review_inflight: set[str] = set()
        self._review_tasks: dict[str, asyncio.Task] = {}
        self._review_backoff: dict[str, float] = {}
        # 审核失败尝试计数（超时/异常）：达上限自动放行进人工复审队列，防无限重试烧 LLM。
        self._review_attempts: dict[str, int] = {}
        # worker trace 事件批量刷盘（见 _persist_worker_trace 注释）
        self._trace_buffer: list[TaskEvent] = []
        self._trace_flush_inflight = False
        self._trace_flush_task: asyncio.Task | None = None
        self._killsweep_inflight: set[str] = set()  # 正在做通杀分析的 finding_id
        self._killsweep_tasks: dict[str, asyncio.Task] = {}
        self._killsweep_cancel_events: dict[str, threading.Event] = {}
        self._escalation_inflight: set[str] = set()  # 正在做扩大危害深挖的 finding_id
        self._escalation_tasks: dict[str, asyncio.Task] = {}
        self._escalation_cancel_events: dict[str, threading.Event] = {}
        # 扩大危害活态（看板展示）
        self._live_escalations: dict[str, dict] = {}
        # 实时看板：每个在跑 worker 的活态 {target_id: {host, url, round, action, started_at, findings}}
        self._live: dict[str, dict] = {}
        self._worker_last_activity: dict[str, float] = {}
        # 人工 mid-run 指令队列：target_id → [directive, ...]（线程安全）
        self._worker_directives: dict[str, list[str]] = {}
        self._worker_directive_lock = threading.Lock()
        # 临时 LLM 错误回队计数（内存级，不耗 retry_count）：防止模型持续抽风时目标无限回队。
        self._transient_llm_requeue: dict[str, int] = {}
        # 企业模式缓存：企业目标多为用户指定的具体资产，不做同款簇冷却/限流
        # （否则 pre-paycenter/test-gateway 等不同子系统会因"同簇打不穿3个"被误跳）。
        # 在 _tick 拿到 task 时刷新。
        self._is_enterprise: bool = False
        # 派发前探活缓存：刚确认存活的 queued 目标短时间内不重复发包。
        self._queue_liveness_ok_until: dict[str, float] = {}
        # 5xx 等临时预筛失败不进终态 skipped，只做短冷却，稍后再探。
        self._queue_prefilter_retry_after: dict[str, float] = {}
        # 端点池全部冷却时按 worker 返回的 retry-after 暂缓该目标，不消耗普通重试次数。
        self._llm_provider_retry_after: dict[str, float] = {}
        # 全池不可用是任务级条件；冷却期间不要让其它 queued 目标逐个启动再回队。
        self._llm_pool_retry_after: float = 0
        # 智能节流状态：{cap, base_cap, reasons, same_org_ratio, updated_at}（供看板展示）。
        self._throttle_state: dict = {}
        # 同机构扎堆占比缓存：(computed_at_loop_time, ratio)；每 30 秒重算一次，避免每 tick 全表 group by。
        self._throttle_org_cache: tuple[float, float] = (0.0, 0.0)
        # 单站协作黑板：只在 site_ 来源任务中按需创建并传给 Worker（懒创建，普通任务不实例化）。
        self._blackboard: Blackboard | None = None

