"""持久化职责：trace 批量刷盘、finding/认证状态/结果落库、LLM 元数据与供应器回调。"""
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


class PersistenceMixin:
    @staticmethod
    def _truncate_trace_payload(payload: dict) -> dict:
        out: dict = {}
        for k, v in (payload or {}).items():
            if k in ("finding",):
                continue
            if k in _TRACE_LONG_KEYS and isinstance(v, str):
                out[k] = v[:2000]
            elif k in _TRACE_TEXT_KEYS and isinstance(v, str):
                out[k] = v[:2000]
            elif isinstance(v, str) and len(v) > 300:
                out[k] = v[:300]
            elif isinstance(v, (str, int, float, bool)) or v is None:
                out[k] = v
            elif isinstance(v, list) and len(v) <= 8:
                out[k] = v
            elif isinstance(v, dict) and len(v) <= 12:
                out[k] = {sk: (sv[:200] if isinstance(sv, str) and len(sv) > 200 else sv)
                          for sk, sv in list(v.items())[:12]
                          if isinstance(sv, (str, int, float, bool, type(None)))}
        return out

    def _schedule_prune_target_traces(self, task_id: str, target_id: str) -> None:
        """worker 结束后异步清细粒度轨迹（保留摘要）；失败不影响主路径。"""
        try:
            t = asyncio.get_running_loop().create_task(prune_target_traces(task_id, target_id))
            t.add_done_callback(lambda f: _log_bg_task_exc(f, "prune_target_traces"))
        except RuntimeError:
            pass

    def _persist_worker_trace(self, task_id: str, target_id: str, kind: str, payload: dict) -> None:
        """选择性缓冲 worker 细粒度事件，由 _trace_flush_loop 批量落库。

        此前每个事件独立 session+commit 打单写者 SQLite：多 worker × 每轮多个工具
        调用 × 3s tick 全部互斥等写锁，锁竞争失败只留 debug 日志静默丢。改为内存
        缓冲 + 周期批量刷盘（trace 是辅助轨迹，崩溃丢缓冲可接受；finding/auth_status
        落库不走此路径，仍实时）。
        """
        if kind not in _WORKER_TRACE_KINDS:
            return
        # 细粒度：活态已摘掉说明 worker 已收尾，跳过迟到的落库，避免清完又写回。
        if kind in TRACE_FINE_KINDS and target_id not in self._live:
            return
        safe = self._truncate_trace_payload(payload)
        msg = ""
        if kind == "worker_thought":
            msg = (safe.get("text") or "")[:300]
        elif kind == "tool_http":
            msg = f"{safe.get('method', 'GET')} {safe.get('url', '')}"[:300]
        elif kind == "tool_shell":
            msg = f"$ {safe.get('command', '')}"[:300]
        elif kind == "worker_directive":
            msg = f"人工指令: {(safe.get('text') or '')[:200]}"
        elif kind in ("llm_error", "tool_exception", "tool_arg_error"):
            msg = str(safe.get("error") or safe.get("message") or kind)[:300]
        else:
            # 无 message 的事件（worker_start / llm_round_start / worker_finish 等）不落库英文
            # kind 作为 message，否则前端 fmtEvent 会优先返回英文；留空让前端走中文 case。
            msg = str(safe.get("message") or "")[:200]
        self._trace_buffer.append(TaskEvent(
            task_id=task_id, agent="worker", kind=kind, level="info",
            message=msg,
            payload={"target_id": target_id, **safe},
        ))
        if len(self._trace_buffer) >= TRACE_FLUSH_BATCH:
            # 不在 emit 回调里等 DB：踢一个后台刷盘，缓冲继续接收。
            self._spawn_trace_flush()

    def _spawn_trace_flush(self) -> None:
        if self._trace_flush_inflight:
            return
        self._trace_flush_inflight = True
        ft = asyncio.create_task(self._flush_trace_buffer())
        ft.add_done_callback(lambda f: _log_bg_task_exc(f, "flush_trace_buffer"))

    async def _flush_trace_buffer(self) -> None:
        batch, self._trace_buffer = self._trace_buffer, []
        self._trace_flush_inflight = False
        if not batch:
            return
        try:
            async with SessionLocal() as session:
                session.add_all(batch)
                await session.commit()
        except Exception:
            logger.debug("trace flush failed (%d events dropped)", len(batch), exc_info=True)

    async def _trace_flush_loop(self) -> None:
        """周期批量刷盘缓冲的 worker 事件；停止后由 stop() 做最后一次 flush。"""
        while not self._stop.is_set():
            await asyncio.sleep(TRACE_FLUSH_INTERVAL)
            await self._flush_trace_buffer()

    async def _log(self, session: AsyncSession, agent: str, kind: str, message: str, level: str = "info", **payload):
        session.add(TaskEvent(task_id=self.task_id, agent=agent, kind=kind, level=level,
                              message=message, payload=payload))
        await session.commit()
        # ts 统一用带 UTC 标识的 ISO 字符串（…+00:00），前端 new Date 才能正确转本地时区。
        await bus.publish(self.task_id, {"agent": agent, "kind": kind, "level": level,
                                         "message": message, "ts": _now_iso(), **payload})

    @staticmethod
    def _llm_payload(llm: LLMClient, model_role: str) -> dict:
        config = getattr(llm, "selected_provider", None)
        return {
            "model_role": model_role,
            "model": getattr(config, "model", "") or "",
            "base_url": getattr(config, "base_url", "") or "",
        }

    @staticmethod
    def _finding_llm_fields(*, model: str = "", base_url: str = "") -> dict:
        """写入 Finding 的模型归因字段（端点池模式下用于事后查看哪个洞由哪个模型打出）。"""
        return {
            "llm_model": str(model or "").strip()[:200],
            "llm_base_url": str(base_url or "").strip()[:300],
        }

    def _live_llm_fields(self, target_id: str) -> dict:
        state = self._live.get(target_id) or {}
        return self._finding_llm_fields(
            model=state.get("model") or "",
            base_url=state.get("model_base_url") or state.get("base_url") or "",
        )

    def _provider_selected_callback(
        self,
        loop: asyncio.AbstractEventLoop,
        target_id: str,
        model_role: str,
    ):
        def on_selected(info: dict) -> None:
            def apply_selection() -> None:
                state = self._live.get(target_id)
                if not state:
                    return
                state["model_role"] = model_role
                state["model"] = str(info.get("model") or "")
                state["model_base_url"] = str(info.get("base_url") or "")

            loop.call_soon_threadsafe(apply_selection)

        return on_selected

    def _provider_failure_callback(self, loop: asyncio.AbstractEventLoop, agent: str, **extra):
        def on_failure(info: dict) -> None:
            payload = {**(info or {}), **extra}
            future = asyncio.run_coroutine_threadsafe(
                self._record_provider_failure(agent, payload),
                loop,
            )
            future.add_done_callback(_consume_task_exception)
        return on_failure

    async def _record_provider_failure(self, agent: str, payload: dict) -> None:
        model = payload.get("model") or ""
        base_url = payload.get("base_url") or ""
        kind = payload.get("kind") or "failed"
        consecutive = int(payload.get("consecutive_failures") or 0)
        cooldown_seconds = int(payload.get("cooldown_seconds") or 0)
        transition = payload.get("transition") or ""
        pool_mode = bool(payload.get("pool_mode"))
        if transition in {"cooldown_probe_failed", "behavior_cooldown_started"}:
            message = (
                f"LLM 进入冷却：{model} @ {base_url}"
                f"（{kind}，连续失败 {consecutive} 次，冷却 {cooldown_seconds} 秒）"
            )
        elif pool_mode:
            message = (
                f"LLM 端点运行失败，正在尝试池内其它端点：{model} @ {base_url}"
                f"（{kind}，连续失败 {consecutive} 次）"
            )
        else:
            # 单端点：不要提「池内换端」，沿用普通失败文案
            message = (
                f"LLM 调用失败：{model} @ {base_url}"
                f"（{kind}，连续失败 {consecutive} 次）"
            )
        event_payload = dict(payload)
        event_payload["error_kind"] = event_payload.pop("kind", kind)
        async with SessionLocal() as session:
            await self._log(
                session,
                agent,
                "llm_provider_failed",
                message,
                level="error",
                **event_payload,
            )

    async def _salvage_findings(self, task_id: str, target_id: str, findings: list) -> None:
        """被取消的 worker 已发现的 findings 抢救落库（只存洞，不改目标状态）。

        与 _persist_worker_result 的落库逻辑一致（dedup + 唯一索引兜底），
        但不触碰目标状态机——目标回队/dead 由 cancel/reclaim 链路自行决定。
        """
        if not findings:
            return
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt:
                return
            target_ref = tgt.url or tgt.host
            worker_id = tgt.assigned_worker
            saved = 0
            for f in findings:
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    continue
                dedup_key = dedup.dedup_key(target_ref, f)
                try:
                    async with session.begin_nested():
                        session.add(Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""),
                            target_url=f.get("target_url", ""), owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), poc_http=f.get("poc_http", ""),
                            raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                            **self._live_llm_fields(target_id),
                        ))
                    saved += 1
                except IntegrityError:
                    continue
            if saved:
                await session.commit()
                await self._log(session, "orchestrator", "salvage",
                                f"被取消的 worker 抢救落库 {saved} 个漏洞（目标 {target_id[:8]}）",
                                level="warn", target_id=target_id, saved=saved)

    async def _persist_auth_status(self, target_id: str, payload: dict) -> None:
        """把凭据使用反馈落到 Target.auth_status + TaskEvent（无明文），刷新后仍可见。"""
        if not payload:
            return
        safe = {
            "used": bool(payload.get("used")),
            "matched": bool(payload.get("matched")),
            "status": str(payload.get("status") or "")[:40],
            "kinds": list(payload.get("kinds") or [])[:8],
            "matched_by": str(payload.get("matched_by") or "")[:40],
            "binding_target": str(payload.get("binding_target") or "")[:200],
            "reason": str(payload.get("reason") or payload.get("message") or "")[:300],
            "cookie_names": list(payload.get("cookie_names") or [])[:30],
            "header_names": list(payload.get("header_names") or [])[:20],
        }
        msg = str(payload.get("message") or "").strip()
        if not msg:
            from app.agents.auth_bootstrap import format_auth_status_message
            msg = format_auth_status_message(safe)
        try:
            async with SessionLocal() as session:
                tgt = await session.get(Target, target_id)
                if not tgt:
                    return
                tgt.auth_status = safe
                session.add(TaskEvent(
                    task_id=self.task_id,
                    agent="worker",
                    kind="auth_status",
                    level="info" if safe["status"] in ("injected", "login_ok") else "warn",
                    message=msg[:500],
                    payload={"target_id": target_id, "host": tgt.host, **safe},
                ))
                await session.commit()
        except Exception:
            logger.warning("persist_auth_status failed target=%s", target_id[:8], exc_info=True)

    async def _persist_single_finding(self, task_id: str, target_id: str, f: dict) -> None:
        """worker 每 submit 一个洞就实时落库，进程被打断时不丢洞。

        幂等：dedup_key + 唯一索引兜底，与 _salvage_findings/_persist_worker_result
        共用同一去重模式，最终整轮落库不会产生重复。只存洞，不碰目标状态机。
        失败静默吞掉——实时落库是「加保险」，整轮 result 落库仍是兜底。
        """
        if not f:
            return
        try:
            async with SessionLocal() as session:
                tgt = await session.get(Target, target_id)
                if not tgt:
                    return
                target_ref = tgt.url or tgt.host
                worker_id = tgt.assigned_worker
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    return
                dedup_key = dedup.dedup_key(target_ref, f)
                llm_fields = self._finding_llm_fields(
                    model=f.get("_llm_model") or f.get("llm_model") or "",
                    base_url=f.get("_llm_base_url") or f.get("llm_base_url") or "",
                )
                if not llm_fields["llm_model"] and not llm_fields["llm_base_url"]:
                    llm_fields = self._live_llm_fields(target_id)
                try:
                    async with session.begin_nested():
                        session.add(Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""),
                            target_url=f.get("target_url", ""), owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), poc_http=f.get("poc_http", ""),
                            raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                            **llm_fields,
                        ))
                    await session.commit()
                except IntegrityError:
                    return
                logger.info("[realtime_persist] target=%s title=%s model=%s 实时落库成功",
                            target_id[:8], (f.get("title") or "")[:40],
                            llm_fields.get("llm_model") or "-")
        except Exception:
            logger.warning("[realtime_persist] target=%s 实时落库失败（整轮 result 仍会兜底）",
                            target_id[:8], exc_info=True)

    async def _heartbeat_target(self, target_id: str) -> None:
        timeout_ref = WORKER_IDLE_TIMEOUT if WORKER_IDLE_TIMEOUT > 0 else WORKER_WALL_TIMEOUT
        interval = max(5.0, min(TARGET_HEARTBEAT_INTERVAL, max(5.0, timeout_ref / 4)))
        while True:
            await asyncio.sleep(interval)
            # 关键：心跳循环绝不能因一次瞬时 DB 异常而整条死掉——否则该 target
            # 停止续心跳，会被 _reclaim_stale 误判成幽灵回收/或在 finally 里把一次
            # 本已成功的 worker 结果连累成 error。单次失败就跳过，下一拍再试。
            try:
                async with SessionLocal() as session:
                    tgt = await session.get(Target, target_id)
                    if not tgt or tgt.status not in ("assigned", "scanning"):
                        return
                    tgt.heartbeat_at = _now()
                    await session.commit()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("TaskRunner[%s] heartbeat tick failed target=%s (will retry)",
                             self.task_id, target_id[:8], exc_info=True)
                continue

    async def _harvest_intel(self, session, task_id: str, tgt, verdict: str,
                             findings: list, reported_intel: list | None = None) -> None:
        """从出洞结果提炼 + worker 主动上报，沉淀可复用情报入全局情报库（不冗余）。

        自动提炼（仅出洞时）：
        - fingerprint：该系统打出过什么漏洞 → 同款系统打法
        - endpoint：漏洞所在路径 → 同款系统有效端点
        - profile：技术栈/系统识别 → 本域画像
        worker 主动上报（reported_intel）：cred/endpoint/profile，无论出洞与否都收。
        """
        host = (tgt.host or "").strip()
        root = target_cluster.root_domain(host)
        fps = intel_lib.detect_fingerprints(host, tgt.title or "", tgt.org or "")
        src_task = task_id

        # ===== worker 主动上报的情报（cred 按 root 域，endpoint 按系统指纹，profile 按 root 域）=====
        for it in (reported_intel or []):
            if not isinstance(it, dict):
                continue
            kind = (it.get("kind") or "").strip().lower()
            payload = it.get("payload") if isinstance(it.get("payload"), dict) else {}
            if not payload:
                continue
            conf = "verified" if it.get("confidence") == "verified" else "likely"
            summ = it.get("summary") or ""
            if kind == "cred" and root:
                await intel_lib.record_intel(session, "cred", root, payload=payload,
                                             summary=summ, source_host=host,
                                             source_task_id=src_task, confidence=conf)
            elif kind == "endpoint":
                # 有系统指纹按指纹存（可跨域复用）；否则退而按 root 域存
                keys = fps or ([root] if root else [])
                for k in keys:
                    await intel_lib.record_intel(session, "endpoint", k, payload=payload,
                                                 summary=summ, source_host=host,
                                                 source_task_id=src_task, confidence=conf)
            elif kind == "profile" and root:
                await intel_lib.record_intel(session, "profile", root, payload=payload,
                                             summary=summ, source_host=host,
                                             source_task_id=src_task, confidence=conf)

        # ===== 自动提炼：只在确认出洞时（质量门槛，防冗余垃圾）=====
        if verdict != Verdict.found.value and not findings:
            return

        for f in findings:
            vuln_type = (f.get("vuln_type") or "").strip()
            title = (f.get("title") or "").strip()
            url = (f.get("target_url") or "").strip()
            if not vuln_type:
                continue
            # 提取路径（endpoint 情报）
            path = ""
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path or ""
            except Exception:
                path = ""

            # fingerprint：同款系统打法（仅当识别出系统指纹时）
            for fp in fps:
                await intel_lib.record_intel(
                    session, "fingerprint", fp,
                    payload={"tactic": f"{vuln_type}：{title}"[:300], "vuln_type": vuln_type},
                    summary=f"{vuln_type}（来自 {host}）",
                    source_host=host, source_task_id=src_task, confidence="verified",
                )
                # endpoint：同款系统有效端点
                if path and path != "/":
                    await intel_lib.record_intel(
                        session, "endpoint", fp,
                        payload={"path": path, "vuln_type": vuln_type},
                        summary=f"（来自 {host} 出洞）",
                        source_host=host, source_task_id=src_task, confidence="verified",
                    )

        # profile：本域技术栈画像（仅当识别出指纹时，记一条系统类型）
        if root and fps:
            await intel_lib.record_intel(
                session, "profile", root,
                payload={"key": "系统类型", "value": ", ".join(fps)},
                summary="", source_host=host, source_task_id=src_task, confidence="likely",
            )

    async def _persist_worker_result(self, task_id: str, target_id: str, result: dict) -> None:
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            if not tgt:
                return
            worker_id = tgt.assigned_worker or ""
            target_ref = tgt.url or tgt.host
            verdict = result.get("verdict", "error")
            findings = result.get("findings", [])
            error_text = result.get("error") or ""
            summary_text = result.get("summary") or ""
            failure_kind = str(result.get("failure_kind") or "").strip()
            provider_cooldown = (
                verdict == Verdict.error.value
                and not findings
                and result.get("failure_kind") == "provider_cooldown"
            )
            auto_converged = (
                verdict == Verdict.no_vuln.value
                and not findings
                and (
                    "系统自动收敛" in summary_text
                    or summary_text.startswith("连续")
                    or summary_text.startswith("模型连续")
                )
            )
            quota_llm_error = (
                verdict == Verdict.error.value
                and not findings
                and self._is_quota_error(error_text)
            )
            transient_llm_error = (
                verdict == Verdict.error.value
                and not findings
                and not provider_cooldown
                and (
                    failure_kind in {
                        "model_behavior", "tool_argument",
                        "rate_limit", "timeout", "network", "upstream",
                        "blocked", "unknown",
                    }
                    or self._is_transient_worker_error(error_text)
                )
            )
            # 自动深挖回火标记（worker 突破有线索时设置，用于日志）。
            auto_deepen_info = None
            # worker 主动回队标记；回队不是终态，不能再记 target_done。
            worker_requeue_info = None
            # 临时错误回队有上限：模型持续抽风时不能让目标无限空转。
            transient_exhausted = False
            if transient_llm_error:
                cnt = self._transient_llm_requeue.get(target_id, 0) + 1
                self._transient_llm_requeue[target_id] = cnt
                if cnt > MAX_TRANSIENT_LLM_REQUEUE:
                    transient_llm_error = False
                    transient_exhausted = True

            runtime = result.get("_runtime") if isinstance(result.get("_runtime"), dict) else {}
            runtime_model = str(runtime.get("model") or "").strip()
            runtime_base_url = str(runtime.get("base_url") or "").strip()
            if runtime_model or runtime_base_url:
                session.add(TaskEvent(
                    task_id=task_id,
                    agent="worker",
                    kind="worker_model",
                    level="info",
                    message="",
                    payload={
                        "target_id": target_id,
                        "model": runtime_model,
                        "base_url": runtime_base_url,
                        "model_role": str(runtime.get("model_role") or "挖掘模型"),
                    },
                ))

            # 落 Finding（含漏洞级去重；DB 唯一索引兜底，逐条 savepoint 容错并发重复）
            saved_findings: list[tuple[dict, Finding]] = []
            for f in findings:
                duplicate = await self._find_existing_duplicate(session, target_ref, f)
                if duplicate:
                    continue
                dedup_key = dedup.dedup_key(target_ref, f)
                try:
                    async with session.begin_nested():
                        finding = Finding(
                            task_id=task_id, target_id=target_id, worker_id=worker_id,
                            vuln_type=f.get("vuln_type", ""), title=f.get("title", ""),
                            severity_claimed=f.get("severity_claimed", ""), target_url=f.get("target_url", ""),
                            owner=f.get("owner", ""),
                            description=f.get("description", ""), steps=f.get("steps", []),
                            poc=f.get("poc", ""), poc_http=f.get("poc_http", ""),
                            raw_request=f.get("raw_request", ""),
                            raw_response=f.get("raw_response", ""), evidence=f.get("evidence", {}),
                            affected_scope=f.get("affected_scope", ""),
                            kill_chain=f.get("kill_chain", []),
                            self_check=f.get("self_check", {}),
                            dedup_key=dedup_key, status="pending_review",
                            **self._finding_llm_fields(
                                model=f.get("_llm_model") or f.get("llm_model") or runtime_model,
                                base_url=f.get("_llm_base_url") or f.get("llm_base_url") or runtime_base_url,
                            ),
                        )
                        session.add(finding)
                    saved_findings.append((f, finding))
                except IntegrityError:
                    continue  # 唯一索引拦下并发/重复，跳过即可

            # 出洞闭环回写：命中通杀记录 affected_table（同 host）的 finding 关联回通杀列，
            # 通杀卡片可展示出洞数并点击查看每份报告。全程降级，不影响主流程落库。
            if saved_findings:
                try:
                    await self._backlink_killsweep(session, task_id, target_ref, saved_findings)
                except Exception:
                    logger.warning("[backlink_killsweep] task=%s target=%s 出洞回写失败",
                                   task_id[:8], target_id[:8], exc_info=True)

            # 情报库沉淀：出洞时从 finding 提炼 + worker 主动上报的情报，入全局库供复用。
            # 全程降级，任何异常都不影响 worker 结果落库。
            try:
                await self._harvest_intel(session, task_id, tgt, verdict, findings,
                                          result.get("reported_intel") or [])
            except Exception:
                pass

            coverage_records: list[dict] = []
            for item in (result.get("reported_coverage") or [])[:20]:
                if not isinstance(item, dict):
                    continue
                route = str(item.get("route") or tgt.source or "site")[:40]
                summary = str(item.get("summary") or "")[:300]
                if not summary:
                    continue
                coverage_record = {
                    "route": route,
                    "summary": summary,
                    "endpoints": (item.get("endpoints") or [])[:20],
                    "remaining": str(item.get("remaining") or "")[:400],
                }
                coverage_records.append(coverage_record)
                session.add(TaskEvent(
                    task_id=task_id,
                    agent="worker",
                    kind="coverage_reported",
                    level="info",
                    message=f"覆盖记录 {tgt.host} / {route}: {summary}",
                    payload={
                        "target_id": target_id,
                        "host": dedup.normalize_host(tgt.url or tgt.host),
                        **coverage_record,
                    },
                ))
            if coverage_records:
                spawned = await self._spawn_site_followups(session, task_id, tgt, coverage_records)
                if spawned:
                    session.add(TaskEvent(
                        task_id=task_id,
                        agent="orchestrator",
                        kind="site_followups_spawned",
                        level="info",
                        message=f"单站协作已根据 {tgt.source} 覆盖记录派生 {spawned} 个定向追打 worker",
                        payload={
                            "target_id": target_id,
                            "host": dedup.normalize_host(tgt.url or tgt.host),
                            "source": tgt.source,
                            "spawned": spawned,
                        },
                    ))

            # 单站协作幂等兜底：主题深挖路线现在已在开局(_site_collect)与侦察路线一起
            # 并发入队，这里不再是必经门禁，只作兜底——万一开局某条主题路线入队失败，
            # discovery 侦察路线跑完后在此补派一次（靠 source 存在性去重，正常情况全跳过=no-op）。
            _theme_deepen_lead = (result.get("deepen_lead") or "").strip()
            _discovery_ok = (verdict == Verdict.no_vuln.value or verdict == Verdict.found.value or findings)
            if _discovery_ok and not _is_actionable_worker_deepen_lead(_theme_deepen_lead):
                theme_spawned = await self._spawn_site_theme_routes(session, task_id, tgt)
                if theme_spawned:
                    session.add(TaskEvent(
                        task_id=task_id,
                        agent="orchestrator",
                        kind="site_theme_routes_spawned",
                        level="info",
                        message=f"单站协作侦察完成（{tgt.source}），已派发 {theme_spawned} 条主题深挖路线",
                        payload={
                            "target_id": target_id,
                            "host": dedup.normalize_host(tgt.url or tgt.host),
                            "source": tgt.source,
                            "spawned": theme_spawned,
                        },
                    ))

            if quota_llm_error:
                tgt.verdict = ""
                tgt.status = "queued"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = ""
                self._apply_resume_context(tgt, result)
                await self._stop_task_for_quota(session, error_text, target_id=target_id)
            elif provider_cooldown:
                retry_after = max(1, int(result.get("retry_after_seconds") or 0))
                self._llm_provider_retry_after[target_id] = (
                    asyncio.get_running_loop().time() + retry_after
                )
                self._llm_pool_retry_after = max(
                    self._llm_pool_retry_after,
                    asyncio.get_running_loop().time() + retry_after,
                )
                tgt.verdict = ""
                tgt.status = "queued"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = ""
                self._apply_resume_context(tgt, result)
            elif transient_llm_error:
                tgt.verdict = ""
                tgt.status = "queued"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = ""
                self._apply_resume_context(tgt, result)
            else:
                tgt.verdict = verdict
            if quota_llm_error:
                pass
            elif provider_cooldown:
                pass
            elif transient_llm_error:
                pass
            elif verdict == Verdict.found.value or findings:
                tgt.status = "done"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = ""
                tgt.dead_reason = ""
            elif verdict == Verdict.no_vuln.value:
                # 自动深挖回火：worker 突破了入口但没打穿，给了 deepen_lead → 带定向指令再派一轮
                # （复用 deepen_count + 任务 deepen_cap 防死循环；优先于收敛/重试/dead）。
                deepen_lead = (result.get("deepen_lead") or "").strip()
                no_vuln_retry_reason = self._no_vuln_retry_reason(tgt)
                task_row = await session.get(Task, task_id)
                cap = deepen_cap_for(task_row)
                if (_is_actionable_worker_deepen_lead(deepen_lead) and verdict == Verdict.no_vuln.value
                        and tgt.deepen_count < cap):
                    _prev_dctx = tgt.deepen_context or {}
                    _prev_origin_fid = _prev_dctx.get("from_finding_id") or ""
                    _prev_origin_src = _prev_dctx.get("source") or ""
                    tgt.deepen_context = {
                        "directive": deepen_lead,
                        "vuln_type": "",
                        "original_title": "",
                        "original_summary": summary_text[:1000],
                        # 链式深挖时携带上一轮 AI/人工深挖的前身 finding，使终态救回仍能定位原始线索
                        "from_finding_id": _prev_origin_fid,
                        "source": _prev_origin_src if _prev_origin_src in ("ai", "user") else "worker_lead",
                    }
                    tgt.deepen_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.retry_count = 0  # 深挖是新方向，不计入普通重试
                    tgt.priority_score = (tgt.priority_score or 0) + 100.0
                    tgt.priority_reason = f"[自动深挖#{tgt.deepen_count}] {deepen_lead[:80]}"
                    tgt.last_error = ""
                    tgt.dead_reason = ""
                    auto_deepen_info = (tgt.host, tgt.deepen_count, deepen_lead[:120])
                elif auto_converged:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = summary_text[:300] or "系统自动收敛，无可利用漏洞"
                elif no_vuln_retry_reason and tgt.retry_count < MAX_RETRY:
                    tgt.retry_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"  # 换角度再挖一次
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = (no_vuln_retry_reason or summary_text or "高价值入口未打穿，回队换角度重试")[:500]
                    tgt.dead_reason = ""
                    worker_requeue_info = (tgt.host, no_vuln_retry_reason, tgt.retry_count)
                else:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = (
                        "高价值入口重试仍无果，无可利用漏洞"
                        if no_vuln_retry_reason else
                        (summary_text[:300] or "本轮确认无可利用漏洞，不再默认重试")
                    )
            elif verdict == "timeout":
                if tgt.retry_count < MAX_RETRY:
                    tgt.retry_count += 1
                    tgt.verdict = ""
                    tgt.status = "queued"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = (result.get("error") or summary_text or "worker 超时，回队重试")[:500]
                    tgt.dead_reason = ""
                    self._apply_resume_context(tgt, result)
                    worker_requeue_info = (tgt.host, "worker 超时", tgt.retry_count)
                else:
                    tgt.status = "dead"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = ""
                    tgt.dead_reason = "超时×重试仍无果"
            elif transient_exhausted:
                tgt.status = "dead"
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = error_text[:500]
                tgt.dead_reason = (
                    f"LLM 持续异常：临时错误回队已达上限 {MAX_TRANSIENT_LLM_REQUEUE} 次，模型服务可能不稳定"
                )[:300]
                self._transient_llm_requeue.pop(target_id, None)
            else:
                tgt.status = "dead"  # error：置 dead 并记因，避免无声卡死
                tgt.assigned_worker = ""
                tgt.heartbeat_at = None
                tgt.last_error = (result.get("error") or "worker 异常")[:500]
                tgt.dead_reason = (result.get("error") or "worker 异常")[:300]
            # 目标已离开「持续临时错误」状态（成功/无果/置dead），清理回队计数避免泄漏累积。
            if not transient_llm_error:
                self._transient_llm_requeue.pop(target_id, None)
            # LLM 端点池：本目标退出冷却态时清理其任务级 retry_after（PR #12）。
            if not provider_cooldown:
                self._llm_provider_retry_after.pop(target_id, None)
            # 深挖回炉终态救回：目标已置 dead 且本轮没产出可替代的新 finding 时，把被
            # superseded 的深挖前身复位为可人工复审——避免「AI 判定值得深挖」的好线索在
            # 深挖没打穿后永久沉底、对所有人工面板不可见（对应问题：打回深挖未升级丢洞）。
            revived_origin_fid = None
            produced_new_finding = (verdict == Verdict.found.value) or bool(findings)
            if tgt.status == "dead" and not produced_new_finding:
                revived_origin_fid = await self._revive_deepen_origin(session, tgt)
            await session.commit()
            if auto_deepen_info:
                host, dc, lead = auto_deepen_info
                await self._log(session, "worker", "auto_deepen",
                                f"目标 {host} 突破入口未打穿，自动定向深挖#{dc}：{lead}",
                                level="info", target_id=target_id, verdict="deepen", findings=0)
            elif quota_llm_error:
                await self._log(session, "orchestrator", "quota_stop",
                                f"LLM/API 额度不足，任务已自动停止: {error_text[:120]}",
                                level="error", target_id=target_id, verdict="quota_stop", findings=0)
            elif provider_cooldown:
                retry_after = max(1, int(result.get("retry_after_seconds") or 0))
                task_row = await session.get(Task, self.task_id)
                pool_mode = resolve_llm_runtime_mode(task_row) == "pool"
                cooldown_label = "模型端点池冷却" if pool_mode else "LLM 暂时不可用"
                await self._log(session, "worker", "target_requeued",
                                f"目标 {tgt.host} 因{cooldown_label}回队，约 {retry_after} 秒后重试: "
                                f"{error_text[:120]}",
                                level="warn", target_id=target_id, verdict="retry", findings=0)
            elif transient_llm_error:
                await self._log(session, "worker", "target_requeued",
                                f"目标 {tgt.host} 因临时 LLM 错误回队列(第 "
                                f"{self._transient_llm_requeue.get(target_id, 0)}/{MAX_TRANSIENT_LLM_REQUEUE} 次): "
                                f"{error_text[:120]}",
                                level="warn", target_id=target_id, verdict="retry", findings=0)
            elif worker_requeue_info:
                host, reason, count = worker_requeue_info
                await self._log(session, "worker", "target_requeued",
                                f"目标 {host} {reason}，回队重试(第 {count}/{MAX_RETRY} 次)",
                                level="info", target_id=target_id, verdict="retry", findings=0)
            elif transient_exhausted:
                await self._log(session, "worker", "target_done",
                                f"目标 {tgt.host} 因 LLM 持续异常收敛置 dead（回队达上限 {MAX_TRANSIENT_LLM_REQUEUE} 次）",
                                level="warn", target_id=target_id, verdict="dead", findings=0)
            else:
                await self._log(session, "worker", "target_done",
                                f"目标 {tgt.host} 完成: {verdict}, {len(findings)} 个漏洞",
                                target_id=target_id, verdict=verdict, findings=len(findings))
            if revived_origin_fid:
                await self._log(session, "orchestrator", "deepen_origin_revived",
                                f"目标 {tgt.host} 深挖回炉未升级，已复位原线索到「AI 未采纳」归档供人工复审",
                                level="info", target_id=target_id, finding_id=revived_origin_fid)
