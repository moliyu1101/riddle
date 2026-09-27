"""调度职责：主循环、目标出队/探活/限流/簇冷却、worker 生命周期、控制面（暂停/停止/跳过）。"""
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


class DispatchMixin:
    def _get_blackboard(self) -> Blackboard:
        """按需创建任务级黑板（线程安全：worker 线程池并发读写）。"""
        if self._blackboard is None:
            self._blackboard = Blackboard(self.task_id)
        return self._blackboard

    def live_workers(self) -> list[dict]:
        return list(self._live.values())

    def live_escalations(self) -> list[dict]:
        return list(self._live_escalations.values())

    def inject_directive(self, target_id: str, directive: str) -> dict:
        """向运行中的 worker 注入人工实时指令，下一轮 LLM 前生效。"""
        text = (directive or "").strip()
        if not text:
            return {"ok": False, "error": "指令不能为空"}
        if target_id not in self._active_workers:
            return {"ok": False, "error": "该目标当前没有运行中的 worker"}
        text = text[:2000]
        with self._worker_directive_lock:
            self._worker_directives.setdefault(target_id, []).append(text)
        live = self._live.get(target_id) or {}
        host = live.get("host") or target_id
        try:
            asyncio.get_running_loop().create_task(bus.publish(self.task_id, {
                "agent": "orchestrator",
                "kind": "worker_directive_queued",
                "target_id": target_id,
                "host": host,
                "text": text[:300],
                "message": f"已向 {host} 排队人工指令（下一轮生效）",
                "ts": _now_iso(),
            }))
        except RuntimeError:
            pass
        return {"ok": True, "target_id": target_id, "host": host, "queued": True}

    def _pop_directive(self, target_id: str) -> str | None:
        with self._worker_directive_lock:
            q = self._worker_directives.get(target_id) or []
            if not q:
                return None
            text = q.pop(0)
            if not q:
                self._worker_directives.pop(target_id, None)
            return text

    def diagnostic_snapshot(self) -> dict:
        return {
            "task_id": self.task_id,
            "stopped": self._stop.is_set(),
            "active_workers": len(self._active_workers),
            "worker_cancel_events": len(self._worker_cancel_events),
            "review_inflight": len(self._review_inflight),
            "review_tasks": len(self._review_tasks),
            "killsweep_inflight": len(self._killsweep_inflight),
            "killsweep_tasks": len(self._killsweep_tasks),
            "escalation_inflight": len(self._escalation_inflight),
            "escalation_tasks": len(self._escalation_tasks),
            "live_workers": [
                {
                    "target_id": item.get("target_id"),
                    "host": item.get("host"),
                    "url": item.get("url"),
                    "round": item.get("round"),
                    "action": item.get("action"),
                    "mode": item.get("mode"),
                    "started_at": item.get("started_at"),
                    "last_activity_at": item.get("last_activity_at"),
                    "findings": item.get("findings"),
                }
                for item in list(self._live.values())[:10]
            ],
        }

    async def recover(self, session: AsyncSession) -> None:
        """重启恢复：assigned/scanning → queued（超重试上限则转 dead 硬骨头库）；不动已有 Finding/Review。"""
        rows = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id, Target.status.in_(["assigned", "scanning"])
            )
        )).scalars().all()
        recovered = 0
        killed = 0
        for tgt in rows:
            # 纯重启波及（从未失败过）不消耗 retry：容器编排连续重启很常见，
            # 不豁免会把从未开挖的目标批量送进硬骨头库（MAX_RETRY=1，重启两次即 dead）。
            # 真正反复失败的目标由失败路径消耗 retry；僵尸回收（_reclaim_stale）维持计数。
            if tgt.retry_count == 0:
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = "进程重启恢复：运行中目标回队重试"
                tgt.dead_reason = ""
                tgt.status = "queued"
                tgt.verdict = ""
                recovered += 1
                continue
            if self._queue_or_dead_after_attempt(tgt, "进程重启恢复：运行中目标回队重试"):
                recovered += 1
            else:
                killed += 1
        await session.commit()
        await self._log(
            session, "orchestrator", "recover",
            f"重启恢复：{recovered} 个进行中目标回退队列，{killed} 个超过重试上限转入硬骨头库",
            recovered=recovered, killed=killed,
        )

    async def run_forever(self) -> None:
        async with SessionLocal() as session:
            await self.recover(session)
        self._trace_flush_task = asyncio.create_task(self._trace_flush_loop())
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:
                tb = traceback.format_exc()
                # 完整 traceback 只进后端日志（服务端可查），不写事件流，避免把 SQL
                # 参数里的 leaked_creds 明文暴露到前端看板。
                logger.warning("TaskRunner[%s] tick error:\n%s", self.task_id, tb)
                summary = self._summarize_exc(exc)
                async with SessionLocal() as s:
                    if self._is_quota_error(tb):
                        await self._stop_task_for_quota(s, tb)
                        await self._log(s, "orchestrator", "quota_stop",
                                        "LLM/API 额度不足，任务已自动停止", level="error")
                    else:
                        # 只记可读的异常摘要（类名+消息），不糊整条 SQL/参数。
                        await self._log(s, "orchestrator", "error",
                                        f"主循环异常: {summary}", level="error")
            await asyncio.sleep(LOOP_INTERVAL)

    async def _tick(self) -> None:
        async with SessionLocal() as session:
            task = await session.get(Task, self.task_id)
            if not task or task.status in ("paused", "stopped"):
                return
            self._is_enterprise = is_enterprise_src(task.src_type)

            # 先清掉被 stop/取消打断留下的「正在入队 x/y」中间态，避免看板永久假卡死。
            # 必须放在派发/搜集之前：_pop_queued 探活可能很慢，不能等 refill 才清。
            fc0 = dict(task.fofa_config or {})
            phase0 = str(fc0.get("collector_phase") or "")
            text0 = str(fc0.get("collector_phase_text") or "")
            if phase0 in ("enrich", "dispatch") and "正在入队" in text0:
                queued0 = await self._count(session, "queued")
                if queued0 >= LOW_WATERMARK:
                    fc0["collector_phase"] = "idle"
                    fc0["collector_phase_text"] = (
                        f"队列充足（queued={queued0}），搜集待命"
                    )
                    task.fofa_config = fc0
                    await session.commit()

            # 1. 先派发已有队列，再跑搜集。
            # 大批量手动入队（如 8000+）可能卡在补凭据/分批 commit 很久；
            # 若先 await refill，worker 会整段空转，看板也像「卡死」。
            self._reap_workers()
            await self._reclaim_stale(session)
            effective_cap = await self._effective_cap(session, task)
            free = effective_cap - len(self._active_workers)
            for _ in range(max(0, free)):
                target = await self._pop_queued(session)
                if not target:
                    break
                self._spawn_worker(task, target)

            # 2. 队列水位低 → 补目标（可能很慢，但不再堵住上面的派发）
            async def collector_progress(phase: str, text: str, payload: dict) -> None:
                # _persist=False：入队中间态只 commit fofa_config 给看板进度条，
                # 不写 TaskEvent（避免「正在入队 x/y」刷屏）。
                data = dict(payload or {})
                persist = data.pop("_persist", True)
                if persist:
                    await self._log(
                        session,
                        "collector",
                        "collector_phase",
                        text,
                        phase=phase,
                        **data,
                    )
                    return
                await session.commit()

            added = await collector.refill(
                session,
                task,
                LOW_WATERMARK,
                progress_cb=collector_progress,
                on_provider_failure=self._provider_failure_callback(
                    asyncio.get_running_loop(),
                    "collector",
                    model_role="搜集模型",
                ),
            )

            # 测绘引擎账号连续无效达阈值 → 自动暂停任务，不再空转刷无效请求。
            fofa_fail = int((task.fofa_config or {}).get("fofa_auth_fail_count", 0))
            if FOFA_AUTH_FAIL_PAUSE_THRESHOLD and fofa_fail >= FOFA_AUTH_FAIL_PAUSE_THRESHOLD:
                last_err = (task.fofa_config or {}).get("last_fofa_error", "")
                from app.engines.sync import engine_display_name
                disp = engine_display_name(resolve_engine_name(task))
                reason = f"{disp} 账号连续 {fofa_fail} 次无效，已自动暂停任务，请检查/更换 {disp} key 后重新启动"
                task.status = "paused"
                await session.commit()
                await self._log(session, "orchestrator", "auto_paused", f"{reason}（最后错误：{last_err}）",
                                fofa_auth_fail=fofa_fail, fofa_error=last_err)
                await self.pause(reason)
                return

            # 测绘引擎每日额度耗尽，连续 12 次（约 12 小时）未恢复 → 自动暂停任务。
            # 适合挂机过夜：额度恢复则自动继续搜集；12 小时都没恢复才停。
            if (task.fofa_config or {}).get("daily_limit_exhausted"):
                dl_count = int((task.fofa_config or {}).get("daily_limit_count", 0))
                last_err = (task.fofa_config or {}).get("last_fofa_error", "")
                from app.engines.sync import engine_display_name
                disp = engine_display_name(resolve_engine_name(task))
                reason = f"{disp} 每日额度耗尽，连续 {dl_count} 次（约 {dl_count} 小时）未恢复，已自动暂停任务"
                task.status = "paused"
                await session.commit()
                await self._log(session, "orchestrator", "auto_paused", f"{reason}（最后错误：{last_err}）",
                                daily_limit_count=dl_count, fofa_error=last_err)
                await self.pause(reason)
                return

            if added:
                fc = task.fofa_config or {}
                cur_q = fc.get("current_query", "")
                skipped_low = fc.get("last_skipped_low", 0)
                skipped_cluster = fc.get("last_skipped_cluster", 0)
                skipped_filter = fc.get("last_skipped_filter", 0)
                msg = f"新增 {added} 个目标入队" + (f"（语法: {cur_q}）" if cur_q else "")
                if skipped_low:
                    msg += f"；{skipped_low} 个低分垃圾资产已跳过"
                if skipped_cluster:
                    msg += f"；{skipped_cluster} 个同款冷却/限流资产已跳过"
                if skipped_filter:
                    msg += f"；{skipped_filter} 个低出货概率资产已过滤"
                await self._log(session, "collector", "refill", msg, added=added,
                                query=cur_q, skipped_low=skipped_low,
                                skipped_cluster=skipped_cluster, skipped_filter=skipped_filter)

            # 3. 入队结束后再补一轮派发（吃掉本轮新进队列）
            self._reap_workers()
            await self._reclaim_stale(session)
            # task.concurrency 是用户在 UI 配的期望并发；worker 实际并发还受全局信号量
            # WORKER_MAX_CONCURRENCY 封顶，并叠加智能节流（队列水位/LLM 健康度/同机构扎堆）。
            # 这里按节流后的 cap 决定本轮 spawn 多少，避免多起的协程只是白白阻塞在
            # worker_sem.acquire()（表现为"配了 N 并发但没那么多在跑"）。
            effective_cap = await self._effective_cap(session, task)
            free = effective_cap - len(self._active_workers)
            for _ in range(max(0, free)):
                target = await self._pop_queued(session)
                if not target:
                    break
                self._spawn_worker(task, target)

            # 4. 派发审核（pending_review → reviewed）
            await self._dispatch_reviews(session, task)

            # 5. idle 标记
            queued = await self._count(session, "queued")
            # 除了 queued 和内存里的活跃 worker，还要看 DB 里有没有 assigned/scanning 的
            # 在途目标：幽灵 scanning(协程已死但状态没回收)期间不能误判 idle，否则前端显示
            # 空闲、实际还有目标虚挂，直到 reclaim(最多 ~150s)才回收——保持 running 更真实。
            inflight = await self._count_inflight(session)
            busy = bool(self._active_workers) or inflight > 0
            if queued == 0 and not busy and task.status == "running":
                if task.status != "idle":
                    task.status = "idle"
                    await session.commit()
            elif task.status == "idle" and (queued or busy):
                task.status = "running"
                await session.commit()

    async def _count(self, session: AsyncSession, status: str) -> int:
        from sqlalchemy import func
        return (await session.execute(
            select(func.count()).select_from(Target).where(
                Target.task_id == self.task_id, Target.status == status)
        )).scalar() or 0

    async def _count_inflight(self, session: AsyncSession) -> int:
        """在途目标数：assigned(已 pop 待起协程) + scanning(挖掘中/幽灵未回收)。
        用于 idle 判定，避免有目标虚挂时把任务误标为空闲。"""
        from sqlalchemy import func
        return (await session.execute(
            select(func.count()).select_from(Target).where(
                Target.task_id == self.task_id,
                Target.status.in_(("assigned", "scanning")))
        )).scalar() or 0

    async def _queued_org_ratio(self, session: AsyncSession) -> float:
        """queued 目标里同机构（school/org）扎堆占比，带 30 秒缓存防每 tick 全表 group by。"""
        loop = asyncio.get_running_loop()
        now = loop.time()
        cached_at, cached = self._throttle_org_cache
        if cached_at and (now - cached_at) < 30.0:
            return cached
        ratio = 0.0
        try:
            rows = (await session.execute(
                select(Target.school, Target.org).where(
                    Target.task_id == self.task_id, Target.status == "queued")
            )).all()
            ratio = same_org_ratio([(r[0] or "", r[1] or "") for r in rows])
        except Exception:
            ratio = 0.0
        self._throttle_org_cache = (now, ratio)
        return ratio

    async def _effective_cap(self, session: AsyncSession, task: Task) -> int:
        """智能节流后的 worker 并发上限：按队列水位 / LLM 健康度 / 同机构扎堆动态调整。"""
        base = min(task.concurrency, WORKER_MAX_CONCURRENCY)
        loop = asyncio.get_running_loop()
        now = loop.time()
        queued = await self._count(session, "queued")
        llm_under_cooldown = self._llm_pool_retry_after > now
        provider_cooldowns = sum(1 for t in self._llm_provider_retry_after.values() if t > now)
        org_ratio = await self._queued_org_ratio(session)
        cap, reasons = compute_effective_cap(
            task.concurrency, WORKER_MAX_CONCURRENCY, queued,
            llm_under_cooldown=llm_under_cooldown,
            llm_provider_cooldowns=provider_cooldowns,
            same_org_ratio=org_ratio,
        )
        self._throttle_state = {
            "cap": cap, "base_cap": base, "reasons": reasons,
            "queued": queued, "same_org_ratio": round(org_ratio, 3),
            "llm_under_cooldown": llm_under_cooldown,
            "provider_cooldowns": provider_cooldowns,
            "updated_at": now,
        }
        return cap

    async def _pop_queued(self, session: AsyncSession) -> Target | None:
        # 按 EduSRC 优先级评分降序派发：高价值目标先挖。
        # 多取一批是为了遇到同款系统正在跑/已冷却时，能跳到其它 cluster。
        loop = asyncio.get_running_loop()
        now = loop.time()
        if self._llm_pool_retry_after > now:
            return None
        self._llm_pool_retry_after = 0
        if self._queue_prefilter_retry_after:
            self._queue_prefilter_retry_after = {
                tid: until for tid, until in self._queue_prefilter_retry_after.items() if until > now
            }
        if self._llm_provider_retry_after:
            self._llm_provider_retry_after = {
                tid: until for tid, until in self._llm_provider_retry_after.items() if until > now
            }
        candidates = (await session.execute(
            select(Target).where(Target.task_id == self.task_id, Target.status == "queued")
            .order_by(Target.priority_score.desc(), Target.created_at).limit(QUEUE_DISPATCH_CANDIDATE_LIMIT)
        )).scalars().all()
        if not candidates:
            return None

        # 是否真的需要簇状态：仅当【非企业】且本批存在“受同款簇冷却/并发限流”的候选时才需要。
        # 企业模式、或本批候选全是 manual/深挖/单站时，下面的全表 load + O(总目标数) 遍历
        # 结果永远不会被读取（见下方按目标的同款簇冷却/并发限流守卫），此处直接短路，避免长跑越跑越慢。
        need_cluster = (not self._is_enterprise) and any(
            (not t.deepen_context and t.source != "manual"
             and not site_collab.is_site_source(t.source)
             and target_cluster.target_cluster_key(t.host or t.url, t.title, t.org))
            for t in candidates
        )
        if need_cluster:
            # 只取簇计算用到的列，不再水化不断增长的 dead/skipped 完整 ORM 实体。
            all_targets = (await session.execute(
                select(
                    Target.host, Target.url, Target.title, Target.org,
                    Target.status, Target.verdict, Target.dead_reason, Target.last_error,
                ).where(
                    Target.task_id == self.task_id,
                    Target.status.in_(["queued", "assigned", "scanning", "dead", "skipped"]),
                )
            )).all()
            cluster_state = self._cluster_state(all_targets)
            active_clusters = {
                target_cluster.target_cluster_key(t.host or t.url, t.title, t.org)
                for t in all_targets
                if t.status in ("assigned", "scanning")
            }
            active_clusters.discard("")
        else:
            cluster_state = {}
            active_clusters = set()

        skipped_cooldown = 0
        eligible: list[Target] = []
        for target in candidates:
            if self._queue_prefilter_retry_after.get(target.id, 0) > now:
                continue
            if self._llm_provider_retry_after.get(target.id, 0) > now:
                continue
            key = target_cluster.target_cluster_key(target.host or target.url, target.title, target.org)
            # 企业模式：目标多为用户指定的具体资产（pre-paycenter/test-gateway 等不同子系统），
            # 不做同款簇冷却/并发限流，每个指定资产都要挖——否则会被"同簇打不穿3个"误跳。
            # 定向深挖目标同样不受同簇冷却影响（人工/审核明确要求继续打穿的例外）。
            # 手动清单（source=manual）是用户明确点名要打的，逐个挖，绝不因同款簇冷却跳过
            # （与低成功率预筛的 manual 豁免保持一致，见 _low_success_skip_reason）。
            if (not self._is_enterprise and not target.deepen_context
                    and target.source != "manual"
                    and not site_collab.is_site_source(target.source) and key):
                state = cluster_state.get(key, {})
                if target_cluster.should_cooldown_cluster(state):
                    target.status = "skipped"
                    target.verdict = "skip_cluster_cooldown"
                    target.dead_reason = target_cluster.cooldown_reason(state, state.get("sample", ""))
                    target.last_error = ""
                    skipped_cooldown += 1
                    continue
                if key in active_clusters:
                    continue

            eligible.append(target)

        if not eligible:
            if skipped_cooldown:
                await session.commit()
                await self._log(
                    session, "orchestrator", "cluster_cooldown_skip",
                    f"派发前跳过 {skipped_cooldown} 个同款冷却目标",
                    level="info", skipped=skipped_cooldown,
                )
            return None

        removed_unreachable = 0
        skipped_low_success = 0
        deferred_transient = 0
        selected: tuple[Target, dict] | None = None
        # 小批探活：不必每次把最多 120 个候选全探完才派发一个 worker。
        # 高分优先的小批里一旦找到可打目标就立刻返回，剩余候选留给下一轮，
        # 避免一堆慢/死站把空闲 worker 卡在调度阶段。
        for i in range(0, len(eligible), QUEUE_LIVENESS_BATCH_SIZE):
            batch = eligible[i:i + QUEUE_LIVENESS_BATCH_SIZE]
            liveness = await self._probe_queued_liveness(batch)
            for target in batch:
                probe = liveness.get(target.id) or {"alive": False}
                if not probe.get("alive"):
                    self._queue_prefilter_retry_after.pop(target.id, None)
                    target.status = "dead"
                    target.verdict = "unreachable"
                    target.assigned_worker = ""
                    target.heartbeat_at = None
                    target.last_error = ""
                    target.dead_reason = (probe.get("reason") or "派发前探活失败：目标访问不了")[:300]
                    removed_unreachable += 1
                    continue

                skip_reason = self._low_success_skip_reason(target, probe)
                if skip_reason:
                    if self._is_transient_prefilter_reason(skip_reason):
                        self._queue_prefilter_retry_after[target.id] = now + QUEUE_TRANSIENT_PREFILTER_COOLDOWN
                        target.status = "queued"
                        target.verdict = ""
                        target.assigned_worker = ""
                        target.heartbeat_at = None
                        target.last_error = skip_reason[:500]
                        target.dead_reason = ""
                        deferred_transient += 1
                        continue
                    self._queue_prefilter_retry_after.pop(target.id, None)
                    target.status = "skipped"
                    target.verdict = "skip_low_success"
                    target.assigned_worker = ""
                    target.heartbeat_at = None
                    target.last_error = ""
                    target.dead_reason = skip_reason[:300]
                    skipped_low_success += 1
                    continue

                if probe.get("alive"):
                    selected = (target, probe)
                    break
            if selected:
                break

        if selected:
            target, probe = selected
            self._queue_prefilter_retry_after.pop(target.id, None)
            target.status = "assigned"
            target.assigned_worker = f"w-{target.id[:8]}"
            target.heartbeat_at = _now()
            target.dead_reason = ""
            target.last_error = ""
            alive_url = probe.get("url") or ""
            if alive_url and alive_url != target.url:
                target.url = alive_url
            await session.commit()
            if removed_unreachable:
                await self._log(
                    session, "orchestrator", "target_unreachable",
                    f"派发前剔除 {removed_unreachable} 个访问不了的目标",
                    level="warn", removed=removed_unreachable,
                )
            if skipped_low_success:
                await self._log(
                    session, "orchestrator", "target_prefilter_skip",
                    f"派发前跳过 {skipped_low_success} 个低成功率目标",
                    level="warn", skipped=skipped_low_success,
                )
            if deferred_transient:
                await self._log(
                    session, "orchestrator", "target_prefilter_defer",
                    f"派发前暂缓 {deferred_transient} 个临时异常目标，稍后重试",
                    level="info", deferred=deferred_transient,
                    cooldown_seconds=QUEUE_TRANSIENT_PREFILTER_COOLDOWN,
                )
            return target

        if skipped_cooldown:
            await session.commit()
            await self._log(
                session, "orchestrator", "cluster_cooldown_skip",
                f"派发前跳过 {skipped_cooldown} 个同款冷却目标",
                level="info", skipped=skipped_cooldown,
            )
        if removed_unreachable:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_unreachable",
                f"派发前剔除 {removed_unreachable} 个访问不了的目标",
                level="warn", removed=removed_unreachable,
            )
        if skipped_low_success:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_prefilter_skip",
                f"派发前跳过 {skipped_low_success} 个低成功率目标",
                level="warn", skipped=skipped_low_success,
            )
        if deferred_transient:
            await session.commit()
            await self._log(
                session, "orchestrator", "target_prefilter_defer",
                f"派发前暂缓 {deferred_transient} 个临时异常目标，稍后重试",
                level="info", deferred=deferred_transient,
                cooldown_seconds=QUEUE_TRANSIENT_PREFILTER_COOLDOWN,
            )
        return None

    async def _probe_queued_liveness(self, targets: list[Target]) -> dict[str, dict]:
        if not targets:
            return {}
        loop = asyncio.get_running_loop()
        now = loop.time()
        results: dict[str, dict] = {}
        pending: list[tuple[str, str, str]] = []
        for target in targets:
            if self._queue_liveness_ok_until.get(target.id, 0) > now:
                results[target.id] = {"alive": True, "url": target.url, "status": 0, "cached": True}
            else:
                pending.append((target.id, target.url, target.host))

        if pending:
            sem = asyncio.Semaphore(max(1, QUEUE_LIVENESS_CONCURRENCY))

            async def one(target_id: str, url: str, host: str) -> tuple[str, dict]:
                async with sem:
                    try:
                        res = await loop.run_in_executor(
                            COLLECTOR_IO_EXECUTOR,
                            lambda: _probe_target_liveness(url, host, QUEUE_LIVENESS_TIMEOUT),
                        )
                    except Exception as exc:
                        res = {
                            "alive": False,
                            "url": url or host,
                            "status": 0,
                            "reason": f"派发前探活异常：{str(exc)[:180]}",
                        }
                    return target_id, res

            for target_id, res in await asyncio.gather(*(one(*item) for item in pending)):
                if res.get("alive") and not res.get("skip"):
                    self._queue_liveness_ok_until[target_id] = now + QUEUE_LIVENESS_CACHE_TTL
                else:
                    self._queue_liveness_ok_until.pop(target_id, None)
                results[target_id] = res

        if len(self._queue_liveness_ok_until) > 1000:
            self._queue_liveness_ok_until = {
                tid: until for tid, until in self._queue_liveness_ok_until.items() if until > now
            }
        return results

    @staticmethod
    def _low_success_skip_reason(target: Target, probe: dict) -> str:
        if not QUEUE_LOW_SUCCESS_SKIP:
            return ""
        # 定向深挖和通杀验证目标是明确有线索的例外，不因低分/静态特征提前拦。
        if target.deepen_context or target.source in ("killsweep", "manual") or site_collab.is_site_source(target.source):
            return ""
        if target.leaked_creds:
            return ""

        reason = str(probe.get("reason") or "")
        if probe.get("skip") and reason:
            if any(marker in reason for marker in _TRANSIENT_UNREACHABLE_REASONS):
                return f"{reason}，本轮不交给 worker，避免消耗 token"
            return f"{reason}，低成功率目标不交给 worker"

        score_reason = (target.priority_reason or "").lower()
        if target.priority_score <= QUEUE_LOW_SUCCESS_SCORE_THRESHOLD and any(
            marker in score_reason for marker in _LOW_SUCCESS_SCORE_MARKERS
        ):
            return (
                f"评分 {target.priority_score:.0f} <= {QUEUE_LOW_SUCCESS_SCORE_THRESHOLD:.1f}，"
                f"命中低成功率特征：{(target.priority_reason or '')[:180]}"
            )
        return ""

    @staticmethod
    def _no_vuln_retry_reason(target: Target) -> str:
        """普通 no_vuln 是否值得再挖一轮。

        默认不重试，避免泛目标在「确认没洞」后继续消耗 LLM；只有已确认的高价值入口
        或已验证可用凭据这类实证线索，才允许用 MAX_RETRY 再换角度打一轮。
        """
        if _has_usable_leaked_cred(target.leaked_creds):
            return "存在已验证可用泄露凭据，值得换角度深挖一次"
        # 单站协作的主题/追打路线（认证越权/未授权/文件/注入/逻辑/定向追打）带着明确 focus
        # 来深挖，打不穿时值得换角度再来一轮；discovery 侦察路线(phase==0)不在此列。
        route = site_collab.route_for_source(target.source or "")
        if route is not None and route.phase != 0:
            return f"单站协作深挖路线（{route.label}），换角度再打一轮"
        score_reason = target.priority_reason or ""
        for marker in _NO_VULN_RETRY_PRIORITY_MARKERS:
            if marker in score_reason:
                return f"命中高价值实证入口({marker.rstrip(':')})，值得换角度验证一次"
        return ""

    @staticmethod
    def _is_transient_prefilter_reason(reason: str) -> bool:
        return any(marker in (reason or "") for marker in _TRANSIENT_UNREACHABLE_REASONS)

    @staticmethod
    def _cluster_state(targets: list[Target]) -> dict[str, dict]:
        state: dict[str, dict] = {}
        for t in targets:
            key = target_cluster.target_cluster_key(t.host or t.url, t.title, t.org)
            if not key:
                continue
            item = state.setdefault(key, {"deadish": 0, "pending": 0, "sample": ""})
            if t.status in ("queued", "assigned", "scanning"):
                item["pending"] += 1
            if DispatchMixin._is_cluster_deadish(t):
                item["deadish"] += 1
                item["sample"] = item.get("sample") or (t.host or t.url)
        return state

    @staticmethod
    def _is_cluster_deadish(t: Target) -> bool:
        reason = (t.dead_reason or t.last_error or "").lower()
        if t.status == "skipped" and t.verdict == "skip_cluster_cooldown":
            return True
        if t.status != "dead":
            return False
        if t.verdict in ("no_vuln", "timeout"):
            return True
        return any(marker in reason for marker in ("无可利用", "无果", "自动收敛", "打不穿", "timeout", "超时"))

    def _spawn_worker(self, task: Task, target: Target) -> None:
        prev = self._active_workers.get(target.id)
        if prev is not None and not prev.done():
            # 同一 target 已有未结束协程：跳过本次派发并保留旧协程。
            # 若继续 spawn 会覆盖 _active_workers 引用与 cancel_event，
            # 新旧协程竞写目标状态 + 双倍烧 LLM token（旧事件未被 set，旧协程不会自行退出）。
            logger.error(
                "[double_spawn] target=%s 已有未结束协程，跳过本次重复派发。", target.id[:8]
            )
            return
        cancel_event = threading.Event()
        self._cancelled_targets.discard(target.id)
        self._worker_cancel_events[target.id] = cancel_event
        t = asyncio.create_task(self._run_worker(task.id, target.id, target.url, cancel_event))
        self._active_workers[target.id] = t

    def _reap_workers(self) -> None:
        done = [tid for tid, t in self._active_workers.items() if t.done()]
        for tid in done:
            task = self._active_workers.pop(tid, None)
            if task:
                # 关键：worker 协程若异常死亡，绝不静默吞掉——记后端日志留痕，
                # 否则又会出现「worker 挖到一半莫名其妙消失」且无从追查。
                try:
                    exc = task.exception()
                except asyncio.CancelledError:
                    exc = None
                except Exception:
                    exc = None
                if exc is not None:
                    logger.error(
                        "TaskRunner[%s] worker coroutine died target=%s: %r",
                        self.task_id, tid[:8], exc,
                        exc_info=(type(exc), exc, exc.__traceback__),
                    )
            self._worker_cancel_events.pop(tid, None)

    async def _reclaim_stale(self, session: AsyncSession) -> None:
        """抢救僵尸目标：处于 assigned/scanning 但已无活跃 worker 协程跟踪的，及时回队。

        关键修复：`assigned`/`scanning` 是在 _spawn_worker 同步设置并同步登记到
        _active_workers 的，所以「状态在挖、却不在 _active_workers」只可能是：
        worker 协程异常死亡、进程重启残留、或控制面清理后状态没归位。这类目标的
        worker 早已不存在，必须尽快回收——绝不能等满 WORKER_WALL_TIMEOUT(默认30min)，
        否则它们会长期虚占「扫描中」、堵住吞吐（历史现象：扫描中虚高 20~30）。

        - 无活跃协程：只给一个短宽限期(STALE_NO_WORKER_GRACE)，过了立即回队；
        - 有活跃协程：不动，由协程自身 idle/max-wall 超时策略管理。
        """
        from datetime import timedelta
        # 关键修正：先用 `in _active_workers` 排除所有「协程还在跑」的目标——
        # 那种"协程在跑、心跳暂时停滞"的情况由协程自身的 idle/max-wall 策略兜底，
        # 不归这里管。因此能走到回收判定的，全是「DB=scanning/assigned 但内存里
        # 没有协程」的幽灵目标（进程重启残留 / 协程异常死亡 / 状态没归位）。
        # 既然没有协程在跑，就没有"打断正在挖的 worker"风险，只需一个覆盖
        # 「spawn→首次心跳」窗口的短宽限即可立即回收，避免幽灵目标长期虚占
        # scanning、reclaim 挤牙膏刷屏（本次事故根因：23 个幽灵 scanning）。
        ghost_cutoff = _now() - timedelta(seconds=STALE_NO_WORKER_GRACE)
        rows = (await session.execute(
            select(Target).where(
                Target.task_id == self.task_id,
                Target.status.in_(["assigned", "scanning"]),
            )
        )).scalars().all()
        reclaimed = 0
        for tgt in rows:
            if tgt.id in self._active_workers:
                continue  # 仍有活跃协程在跑，不动（协程自带墙钟超时）
            hb = tgt.heartbeat_at
            if hb is not None and hb.tzinfo is None:
                hb = hb.replace(tzinfo=timezone.utc)
            # 无协程跟踪 + （从未写心跳 或 心跳停滞超短宽限）→ 幽灵目标，立即回收。
            if hb is None or hb < ghost_cutoff:
                hb_age = "None" if hb is None else f"{int((_now() - hb).total_seconds())}s"
                # 诊断：记录被回收目标的现场，便于判断是真幽灵还是误判活跃 worker。
                logger.warning(
                    "[reclaim] target=%s host=%s hb_age=%s in_active=%s active_total=%d",
                    tgt.id[:8], (tgt.url or "")[:40], hb_age,
                    tgt.id in self._active_workers, len(self._active_workers),
                )
                if self._queue_or_dead_after_attempt(tgt, "僵尸目标回收：worker 协程已不存在"):
                    reclaimed += 1
        if reclaimed:
            await session.commit()
            await self._log(session, "orchestrator", "reclaim",
                            f"抢救 {reclaimed} 个僵尸目标回退队列", level="warn", reclaimed=reclaimed)

    async def pause(self, reason: str = "任务暂停") -> None:
        """暂停调度并收回正在跑的 worker。已进入同步调用的线程会收到取消标记，结果不再落库。"""
        await self._cancel_active_workers(f"{reason}：运行中 worker 已取消并回队")

    async def stop(self, reason: str = "任务停止") -> None:
        """停止 runner，并取消 worker/reviewer/killsweep 的后续落库。"""
        self._stop.set()
        if self._trace_flush_task is not None:
            self._trace_flush_task.cancel()
            self._trace_flush_task = None
        await self._cancel_active_workers(f"{reason}：运行中 worker 已取消并回队")
        self._cancel_review_tasks(reason)
        self._cancel_killsweep_tasks(reason)
        self._cancel_escalation_tasks(reason)
        # 停止前的最后一次批量落库，缓冲里的事件不留死角。
        await self._flush_trace_buffer()

    async def _cancel_active_workers(self, reason: str) -> None:
        target_ids = list(self._active_workers.keys())
        if not target_ids:
            return
        for tid in target_ids:
            self._cancelled_targets.add(tid)
            if ev := self._worker_cancel_events.get(tid):
                ev.set()
            if task := self._active_workers.get(tid):
                task.cancel()
            self._live.pop(tid, None)

        async with SessionLocal() as session:
            rows = (await session.execute(
                select(Target).where(Target.task_id == self.task_id, Target.id.in_(target_ids))
            )).scalars().all()
            for tgt in rows:
                if tgt.status in ("assigned", "scanning"):
                    tgt.status = "queued"
                    tgt.verdict = ""
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = reason[:500]
                    tgt.dead_reason = ""
            await session.commit()
            await self._log(
                session, "orchestrator", "workers_cancelled",
                f"{reason}，已收回 {len(rows)} 个目标",
                level="warn", count=len(rows),
            )

    async def skip_target(self, target_id: str, reason: str = "用户手动删除该目标") -> dict:
        """人工从看板删除某个目标：取消其在跑 worker（若有），并把目标标记 skipped——
        使其不再被派发、回队或被 collector 重新收集。仅影响本任务的目标列表。

        依赖 _cancelled_targets：被取消 worker 的迟到结果在 _run_worker_inner 里会被丢弃、
        不会把 skipped 覆盖回 queued/done（已挖到的 findings 仍由 salvage 单独保住，不丢洞）。
        """
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt or tgt.task_id != self.task_id:
                return {"ok": False, "error": "目标不存在或不属于该任务"}
            host = tgt.host or tgt.url or target_id
            # 1) 取消在跑 worker（若有）：标记 cancelled + 触发 cancel_event + 取消协程 + 清活态
            self._cancelled_targets.add(target_id)
            if ev := self._worker_cancel_events.get(target_id):
                ev.set()
            if t := self._active_workers.pop(target_id, None):
                t.cancel()
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            self._worker_cancel_events.pop(target_id, None)
            # 2) 标 skipped：_pop_queued 只取 queued，故不再派发；collector 的 seen 含 skipped，
            #    故不会被重新收集回来（这正是“回收完还继续跑”的修复点）。
            tgt.status = "skipped"
            tgt.verdict = "user_skipped"
            tgt.assigned_worker = ""
            tgt.heartbeat_at = None
            tgt.dead_reason = (reason or "用户手动删除")[:300]
            tgt.last_error = ""
            await session.commit()
            await self._log(
                session, "orchestrator", "target_skipped",
                f"用户从看板删除目标 {host}，已跳过（取消挖掘，不再派发/回队/收集）",
                level="warn", target_id=target_id, host=host,
            )
        return {"ok": True, "target_id": target_id, "host": host}
