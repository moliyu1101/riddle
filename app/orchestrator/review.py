"""审核职责：AI 初审派发、退避与放行、打回深挖、额度熔断。"""
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


class ReviewMixin:
    def _cancel_review_tasks(self, reason: str) -> None:
        for finding_id, task in list(self._review_tasks.items()):
            task.cancel()
            self._review_backoff[finding_id] = asyncio.get_running_loop().time() + REVIEW_RETRY_BACKOFF
        self._review_tasks.clear()
        self._review_inflight.clear()

    @staticmethod
    def _is_transient_worker_error(error: str) -> bool:
        text = (error or "").lower()
        if not any(k in text for k in ("llm 调用失败", "llm 请求", "llm 网络", "llm 上游", "llm 端点")):
            return False
        if ReviewMixin._is_quota_error(error):
            return False
        if any(k in text for k in ("api key", "unauthorized", "无权限", "invalid api")):
            return False
        markers = (
            "rate limit", "限流", "too many requests", "429",
            "timeout", "timed out", "超时",
            "network", "connection", "连接失败",
            "temporarily", "temporary", "upstream", "临时异常", "上游",
            "冷却", "cooldown", "blocked", "策略", "cyber",
            # 模型服务偶发抽风返回的「未知错误」也是临时性的：不该消耗 retry/置 dead，
            # 否则模型一抖动就把还能挖的目标白白打死（实测 20 个目标这么死的）。
            "未知错误", "模型服务返回", "底层细节已脱敏",
        )
        return any(m in text for m in markers)

    @staticmethod
    def _is_quota_error(error: str) -> bool:
        text = (error or "").lower()
        return any(k in text for k in ("额度不足", "余额不足", "insufficient_quota", "billing", "balance"))

    @staticmethod
    def _summarize_exc(exc: BaseException) -> str:
        """把异常压成可读诊断：异常类型 + 首行消息，专治 SQLAlchemy 把整条
        SQL 语句和全部参数（含 leaked_creds 明文）糊进 str(exc) 的问题——那既看不到
        病根，又会把敏感数据写进事件流。这里只取类名 + 消息首行，并砍掉 SQL 语句体。
        """
        parts: list[str] = []
        seen: set[int] = set()
        cur: BaseException | None = exc
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            cls = type(cur).__name__
            msg = str(cur)
            # SQLAlchemy: 消息形如 "(sqlite3.IntegrityError) UNIQUE ... [SQL: INSERT ...] [parameters: ...]"
            # 只保留到 [SQL: 之前的核心报错，丢弃 SQL 语句体与参数（可能含明文凭证）。
            for cut in ("\n[SQL:", " [SQL:", "[SQL:", "[parameters:"):
                idx = msg.find(cut)
                if idx != -1:
                    msg = msg[:idx]
            msg = " ".join(msg.split())[:200]
            parts.append(f"{cls}: {msg}" if msg else cls)
            cur = cur.__cause__ or cur.__context__
            if len(parts) >= 4:
                break
        return " ← ".join(parts)

    async def _stop_task_for_quota(self, session: AsyncSession, error: str, **payload) -> None:
        task = await session.get(Task, self.task_id)
        if task and task.status != "stopped":
            task.status = "stopped"
            await session.commit()
        self._stop.set()

    async def _dispatch_reviews(self, session: AsyncSession, task: Task) -> None:
        pending = (await session.execute(
            select(Finding).where(Finding.task_id == self.task_id, Finding.status == "pending_review").limit(5)
        )).scalars().all()
        now = asyncio.get_running_loop().time()
        # 顺带清扫已过期的 review backoff 条目：exp<=now 与“不存在（默认 0）”在下方
        # `.get(f.id, 0) > now` 判定里完全等价，删除是纯内存回收、100% 行为不变，
        # 避免长任务里 _review_backoff 只增不删的慢泄漏。
        if self._review_backoff:
            for _expired_fid in [k for k, exp in self._review_backoff.items() if exp <= now]:
                del self._review_backoff[_expired_fid]
        for f in pending:
            if f.id in self._review_inflight:
                continue
            if self._review_backoff.get(f.id, 0) > now:
                continue
            self._review_inflight.add(f.id)
            self._review_tasks[f.id] = asyncio.create_task(self._run_review(task.id, f.id))

    async def _review_fail_once(self, finding_id: str, task_id: str, reason: str) -> None:
        """审核一次失败（超时/异常）：进退避并计数；达上限自动放行进人工复审队列。

        此前超时/异常只退避不计数，慢 provider 下 finding 每 5 分钟重审一次永不收敛，
        无限白烧审核 LLM 调用。放行 = 写一条 confidence=uncertain 的 accepted 审核记录
        （severity 按 worker 自评兜底，不触发通杀/扩大危害），由人工做最终裁决。
        """
        loop = asyncio.get_running_loop()
        attempts = self._review_attempts.get(finding_id, 0) + 1
        self._review_attempts[finding_id] = attempts
        self._review_backoff[finding_id] = loop.time() + REVIEW_RETRY_BACKOFF
        if attempts < REVIEW_MAX_ATTEMPTS:
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "review_deferred",
                                f"{reason}，保留 pending_review 稍后重试"
                                f"（第 {attempts}/{REVIEW_MAX_ATTEMPTS} 次）",
                                level="warn", finding_id=finding_id)
            return
        self._review_attempts.pop(finding_id, None)
        self._review_backoff.pop(finding_id, None)
        async with SessionLocal() as s:
            f = await s.get(Finding, finding_id)
            if f is None:
                return
            f.status = "reviewed"
            s.add(Review(
                finding_id=finding_id, task_id=task_id,
                verdict="accepted", confidence="uncertain",
                severity_final=f.severity_claimed or None, score=0.0,
                in_scope=True, is_duplicate=False,
                ignore_reasons=[], downgrade_reasons=[],
                reproduced=False,
                reviewer_notes=(
                    f"[系统] AI 初审连续 {attempts} 次失败（{reason}），已自动放行进人工复审队列，"
                    "请人工核实后裁决。"
                ),
            ))
            await s.commit()
            await self._log(s, "reviewer", "review_giveup",
                            f"审核连续 {attempts} 次失败（{reason}），已放行进人工复审队列",
                            level="error", finding_id=finding_id)

    async def _run_review(self, task_id: str, finding_id: str) -> None:
        # try/finally 兜底：任何异常路径都释放 inflight，避免 finding 永久卡死不被审核
        try:
            await self._run_review_inner(task_id, finding_id)
        except Exception:
            # 前置阶段(如 FindingSchema 校验)抛错不会经过 _run_review_inner 里的
            # 退避分支，这里补一份退避，否则脏数据 finding 会被每个派发周期(3s)重捞重试，
            # 错误事件无限刷屏（实测一晚堆了 1.6 万条）。
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "error",
                                f"审核协程异常: {traceback.format_exc()[:400]}", level="error",
                                finding_id=finding_id)
            await self._review_fail_once(finding_id, task_id, "审核协程异常")
        finally:
            self._review_inflight.discard(finding_id)
            self._review_tasks.pop(finding_id, None)

    async def _run_review_inner(self, task_id: str, finding_id: str) -> None:
        loop = asyncio.get_running_loop()
        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return
            task_obj = await session.get(Task, task_id)
            src_type = (task_obj.src_type if task_obj else "edusrc") or "edusrc"
            src_rules = (task_obj.src_rules if task_obj else "") or ""
            guard_ops = (task_obj.guard_ops if task_obj else []) or []
            finding_schema = FindingSchema(
                vuln_type=f.vuln_type, title=f.title, severity_claimed=f.severity_claimed,
                target_url=f.target_url, description=f.description, steps=f.steps,
                poc=f.poc, raw_request=f.raw_request, raw_response=f.raw_response,
                evidence=f.evidence or {}, affected_scope=f.affected_scope,
                kill_chain=f.kill_chain or [], self_check=f.self_check or {},
                owner=f.owner or "",
            )
            llm = _llm_for_task(
                task_obj,
                on_provider_failure=self._provider_failure_callback(
                    loop, "reviewer", finding_id=finding_id
                ),
            )

        def emit(kind: str, data: dict):
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "reviewer", "kind": kind, "finding_id": finding_id,
                                      "ts": _now_iso(), **data}),
                loop,
            )

        def do_review() -> dict:
            reviewer = Reviewer(llm=llm, on_event=emit, src_type=src_type, src_rules=src_rules,
                                guard_ops=guard_ops)
            return reviewer.review(finding_schema).model_dump(mode="json")

        review_sem = agent_semaphore("review")
        await review_sem.acquire()
        try:
            review_future = loop.run_in_executor(AGENT_EXECUTOR, do_review)
        except BaseException:
            # submit 本身抛错(如池已关闭)——立即归还信号量，否则并发位永久丢失。
            review_sem.release()
            raise

        def _release_review(fut: asyncio.Future) -> None:
            review_sem.release()
            _consume_task_exception(fut)  # 超时/取消后 future 仍在后台跑，消费异常防告警

        review_future.add_done_callback(_release_review)
        try:
            rv = await asyncio.wait_for(
                asyncio.shield(review_future),
                timeout=REVIEW_WALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            await self._review_fail_once(finding_id, task_id,
                                         f"审核超时(>{int(REVIEW_WALL_TIMEOUT)}s)")
            return
        except asyncio.CancelledError:
            # 控制面取消（暂停/停止任务）不计入失败尝试：任务重跑后应继续正常审核。
            self._review_backoff[finding_id] = loop.time() + REVIEW_RETRY_BACKOFF
            async with SessionLocal() as s:
                await self._log(s, "reviewer", "review_cancelled",
                                "审核任务被控制面取消，保留 pending_review，稍后重试",
                                level="warn", finding_id=finding_id)
            return
        except Exception as e:
            if self._is_quota_error(str(e)):
                async with SessionLocal() as s:
                    await self._stop_task_for_quota(s, str(e), finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"审核阶段检测到 LLM/API 额度不足，任务已自动停止: {str(e)[:120]}",
                                    level="error", finding_id=finding_id)
                return
            await self._review_fail_once(finding_id, task_id, f"审核异常: {str(e)[:160]}")

        # accepted 必须有最终等级；LLM 漏填时按 worker 自评兜底，避免最终列表等级空白
        if rv.get("verdict") == "accepted" and not rv.get("severity_final"):
            async with SessionLocal() as s:
                f0 = await s.get(Finding, finding_id)
                rv["severity_final"] = (f0.severity_claimed if f0 else None) or "中危"
            rv["reviewer_notes"] = (rv.get("reviewer_notes", "") +
                                    "\n[系统] 审核未给最终等级，已按 worker 自评兜底。").strip()

        escalate_finding = False
        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if f:
                session.add(Review(
                    finding_id=finding_id, task_id=task_id,
                    verdict=rv["verdict"], confidence=rv["confidence"],
                    severity_final=rv.get("severity_final"), score=rv["score"],
                    in_scope=rv["in_scope"], is_duplicate=rv.get("is_duplicate", False),
                    ignore_reasons=rv.get("ignore_reasons", []),
                    downgrade_reasons=rv.get("downgrade_reasons", []),
                    reproduced=rv.get("reproduced", False), reviewer_notes=rv.get("reviewer_notes", ""),
                    deepen_directive=rv.get("deepen_directive", ""),
                ))
                extra = ""
                if rv["verdict"] == "deepen":
                    extra = await self._apply_deepen(session, f, rv)
                else:
                    f.status = "reviewed"
                # 审核反馈闭环：把初审 accepted（有效打法 PoC 模板）/ ignored（易踩坑半成品注意）
                # 按系统指纹沉淀进情报库，后续同系统 worker 开局即得经验。失败降级不影响主流程。
                try:
                    await intel_lib.emit_review_lessons(
                        session,
                        finding={
                            "vuln_type": f.vuln_type, "title": f.title,
                            "target_url": f.target_url, "owner": f.owner or "",
                            "poc": f.poc, "raw_request": f.raw_request,
                        },
                        review=rv,
                    )
                except Exception:
                    pass
                await session.commit()
                await self._log(session, "reviewer", "review_done",
                                f"审核「{f.title}」: {rv['verdict']} {rv.get('severity_final') or ''}{extra}",
                                finding_id=finding_id, verdict=rv["verdict"],
                                severity=rv.get("severity_final"), score=rv["score"])
                self._review_attempts.pop(finding_id, None)
                # 通杀 Hunter 不在 AI accepted 后触发；必须等人工复审 passed 后再启动。
                # 扩大危害 Hunter：AI accepted 后自动触发（仅对有纵向升级空间的洞），
                # 顺着已确认据点再打一层，显著升级才产出新 finding，否则丢弃。
                escalate_finding = (
                    rv["verdict"] == "accepted"
                    and f.worker_id != "escalation"  # 断递归：升级洞不再触发升级
                    and should_escalate(f.vuln_type, f.title, rv.get("severity_final") or "")
                )
        # commit 之后、脱离 session 再触发，避免把后台任务寿命绑在本次事务上。
        if escalate_finding:
            self.trigger_escalation(task_id, finding_id, rv.get("severity_final") or "")

    async def _apply_deepen(self, session: AsyncSession, finding: Finding, rv: dict) -> str:
        """审核打回深挖：复用共享回炉逻辑（与人工复审「继续深挖」同一套）。"""
        from app.agents.deepen import apply_deepen, deepen_cap_for
        tgt = await session.get(Target, finding.target_id)
        task_row = await session.get(Task, finding.task_id) if finding.task_id else None
        _ok, suffix = apply_deepen(session, finding, tgt,
                                   rv.get("deepen_directive") or "", source="ai",
                                   cap=deepen_cap_for(task_row))
        return suffix
