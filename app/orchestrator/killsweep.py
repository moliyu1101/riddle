"""通杀与扩大危害职责：批量验证编排、资产入队、Escalate 深化。"""
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


class KillsweepMixin:
    def cancel_escalation(self, finding_id: str, reason: str = "用户取消扩大危害") -> dict:
        """取消单个正在进行的扩大危害任务。"""
        if finding_id not in self._escalation_inflight and finding_id not in self._escalation_tasks:
            return {"ok": False, "error": "该洞当前没有进行中的扩大危害"}
        if ev := self._escalation_cancel_events.get(finding_id):
            ev.set()
        if t := self._escalation_tasks.get(finding_id):
            t.cancel()
        live = self._live_escalations.pop(finding_id, None) or {}
        title = live.get("title") or finding_id
        try:
            asyncio.get_running_loop().create_task(bus.publish(self.task_id, {
                "agent": "escalation",
                "kind": "escalate_cancelled",
                "finding_id": finding_id,
                "message": f"扩大危害已取消：{title}",
                "reason": reason,
                "ts": _now_iso(),
            }))
        except RuntimeError:
            pass
        return {"ok": True, "finding_id": finding_id, "title": title}

    def _cancel_killsweep_tasks(self, reason: str) -> None:
        for ev in self._killsweep_cancel_events.values():
            ev.set()
        for task in list(self._killsweep_tasks.values()):
            task.cancel()
        self._killsweep_tasks.clear()
        self._killsweep_inflight.clear()
        self._killsweep_cancel_events.clear()

    def _cancel_escalation_tasks(self, reason: str) -> None:
        for ev in self._escalation_cancel_events.values():
            ev.set()
        for task in list(self._escalation_tasks.values()):
            task.cancel()
        self._escalation_tasks.clear()
        self._escalation_inflight.clear()
        self._escalation_cancel_events.clear()
        self._live_escalations.clear()

    async def _backlink_killsweep(self, session: AsyncSession, task_id: str,
                                  target_ref: str, saved_findings: list[tuple[dict, Finding]]) -> None:
        """出洞闭环回写：Worker 产出的 finding 若命中某通杀记录的 affected_table（同 host），
        把 finding 关联回该通杀记录（derived_findings），通杀列可展示出洞数并点击查看报告。"""
        fhost = collector.normalize_host(target_ref)
        if not fhost:
            return
        rows = (await session.execute(
            select(Killsweep).where(
                Killsweep.task_id == task_id,
                Killsweep.is_killsweep == True,  # noqa: E712
            )
        )).scalars().all()
        if not rows:
            return
        for f, finding in saved_findings:
            fhost = collector.normalize_host(f.get("target_url") or target_ref)
            if not fhost:
                continue
            for row in rows:
                table = row.affected_table or []
                matched = any(
                    collector.normalize_host(str(it.get("url") or it.get("host") or "")) == fhost
                    for it in table
                )
                if not matched:
                    continue
                derived = list(row.derived_findings or [])
                if any(d.get("finding_id") == finding.id for d in derived):
                    continue
                derived.append({
                    "finding_id": finding.id,
                    "title": f.get("title", ""),
                    "school": f.get("owner", ""),
                    "host": fhost,
                    "status": "pending_review",
                    "severity": f.get("severity_claimed", ""),
                    "created_at": _now_iso(),
                })
                row.derived_findings = derived
                row.updated_at = _now()

    async def _killsweep_row_for_finding(self, session: AsyncSession, finding_id: str) -> Killsweep | None:
        return (await session.execute(
            select(Killsweep)
            .where(Killsweep.origin_finding_id == finding_id)
            .order_by(Killsweep.created_at.desc())
        )).scalars().first()

    async def _upsert_killsweep_start(self, task_id: str, finding_id: str) -> str | None:
        """通杀一开始就落库（analyzing），失败/无命中也能出现在通杀列，不必改复审状态重来。"""
        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return None
            row = await self._killsweep_row_for_finding(session, finding_id)
            pending_key = f"pending:{finding_id}"
            if row:
                row.status = "analyzing"
                row.notes = ""
                row.is_killsweep = False
                row.verified = False
                row.verified_url = ""
                row.affected_table = []
                row.derived_findings = []
                row.progress = {
                    "stage": "start",
                    "label": _KILLSWEEP_STAGE_LABEL["start"],
                    "pct": _KILLSWEEP_STAGE_PCT["start"],
                    "ts": _now_iso(),
                }
                row.fail_reason = ""
                if not row.product_key or row.product_key.startswith("pending:"):
                    row.product_key = pending_key
                if not row.vuln_type:
                    row.vuln_type = f.vuln_type or ""
                if not row.vuln_summary:
                    row.vuln_summary = f.title or ""
                row.updated_at = _now()
            else:
                row = Killsweep(
                    task_id=task_id,
                    origin_finding_id=finding_id,
                    product_key=pending_key,
                    product_name="",
                    vuln_type=f.vuln_type or "",
                    vuln_summary=f.title or "",
                    status="analyzing",
                    is_killsweep=False,
                )
                session.add(row)
            await session.commit()
            await session.refresh(row)
            await self._log(
                session, "killsweep", "killsweep_start",
                f"通杀 Hunter 启动：{f.title or finding_id}",
                finding_id=finding_id, killsweep_id=row.id, title=f.title or "",
            )
            return row.id

    async def _mark_killsweep(self, finding_id: str, **fields) -> None:
        async with SessionLocal() as session:
            row = await self._killsweep_row_for_finding(session, finding_id)
            if not row:
                return
            for key, value in fields.items():
                setattr(row, key, value)
            row.updated_at = _now()
            await session.commit()

    async def trigger_killsweep(self, task_id: str, finding_id: str) -> bool:
        """启动通杀分析（复审通过或通杀列手动重启）；finding 级 inflight 去重，避免重复点击。"""
        if finding_id in self._killsweep_inflight:
            return False
        self._killsweep_inflight.add(finding_id)
        try:
            await self._upsert_killsweep_start(task_id, finding_id)
        except Exception:
            self._killsweep_inflight.discard(finding_id)
            raise
        self._killsweep_tasks[finding_id] = asyncio.create_task(self._run_killsweep(task_id, finding_id))
        return True

    async def _run_killsweep(self, task_id: str, finding_id: str) -> None:
        """通杀 Hunter：人工复审通过后，分析该漏洞所在系统能否一打一片。
        按产品指纹去重；判定可通杀且验证成功 → 把那个同款站点入挖掘队列出货。"""
        try:
            await self._run_killsweep_inner(task_id, finding_id)
        except Exception:
            err = traceback.format_exc()[:400]
            await self._mark_killsweep(finding_id, status="failed", fail_reason="other",
                                       notes=f"通杀分析异常: {err}")
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "error",
                                f"通杀分析异常: {err}", level="error",
                                finding_id=finding_id)
        finally:
            self._killsweep_inflight.discard(finding_id)
            self._killsweep_tasks.pop(finding_id, None)
            self._killsweep_cancel_events.pop(finding_id, None)

    async def _run_killsweep_inner(self, task_id: str, finding_id: str) -> None:
        from app.agents.killsweep import KillsweepHunter, product_key
        loop = asyncio.get_running_loop()

        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                await self._mark_killsweep(finding_id, status="failed", notes="源漏洞已不存在")
                return
            task = await session.get(Task, task_id)
            engine_cfg = resolve_engine_config(task)
            engine_name = engine_cfg["engine"]
            fofa_key = engine_cfg["key"]
            fofa_base_url = engine_cfg["base_url"]
            src_type = (task.src_type if task else "edusrc") or "edusrc"
            finding_dict = {
                "title": f.title, "vuln_type": f.vuln_type, "target_url": f.target_url,
                "owner": f.owner, "description": f.description, "poc": f.poc,
                "raw_response": f.raw_response,
            }
            origin_host = f.target_url

        if not fofa_key:
            from app.engines.sync import engine_display_name
            disp = engine_display_name(engine_name)
            msg = (
                f"无 {disp} key，跳过通杀分析（通杀圈定依赖测绘引擎，"
                f"请在设置中为 {disp} 配置 key）"
            )
            await self._mark_killsweep(finding_id, status="failed", fail_reason="no_key", notes=msg)
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "skip",
                                msg, level="warn", finding_id=finding_id)
            return

        llm = _llm_for_task(
            await self._get_task(task_id),
            on_provider_failure=self._provider_failure_callback(
                loop, "killsweep", finding_id=finding_id
            ),
        )
        cancel_event = threading.Event()
        self._killsweep_cancel_events[finding_id] = cancel_event

        def emit(kind: str, data: dict):
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "killsweep", "kind": kind, "finding_id": finding_id,
                                      "ts": _now_iso(), **data}),
                loop,
            )
            stage = _KILLSWEEP_STAGE_MAP.get(kind)
            if stage:
                asyncio.run_coroutine_threadsafe(
                    self._mark_killsweep(finding_id, progress={
                        "stage": stage,
                        "label": _KILLSWEEP_STAGE_LABEL[stage],
                        "pct": _KILLSWEEP_STAGE_PCT[stage],
                        "ts": _now_iso(),
                    }),
                    loop,
                )

        def do_hunt() -> dict:
            hunter = KillsweepHunter(
                finding_dict, fofa_key, llm=llm, on_event=emit,
                src_type=src_type, cancel_event=cancel_event,
                fofa_base_url=fofa_base_url, engine=engine_name,
                src_rules=(task.src_rules if task else "") or "",
                guard_ops=(task.guard_ops if task else []) or [],
            )
            try:
                return hunter.run().model_dump(mode="json")
            finally:
                # 正常完成清理：只杀子进程，不污染 cancel_event（同 worker 修复）。
                hunter.executor.kill_processes()

        killsweep_sem = agent_semaphore("killsweep")
        try:
            await asyncio.wait_for(killsweep_sem.acquire(), timeout=AGENT_SEM_ACQUIRE_TIMEOUT)
        except asyncio.TimeoutError:
            async with SessionLocal() as s:
                await self._log(s, "orchestrator", "killsweep_deferred",
                                f"通杀并发位等待超时(>{int(AGENT_SEM_ACQUIRE_TIMEOUT)}s)，稍后重试",
                                level="warn", finding_id=finding_id)
            return
        try:
            hunt_future = loop.run_in_executor(AGENT_EXECUTOR, do_hunt)
        except BaseException:
            killsweep_sem.release()
            raise

        def _release_killsweep(fut: asyncio.Future) -> None:
            killsweep_sem.release()
            _consume_task_exception(fut)

        hunt_future.add_done_callback(_release_killsweep)
        try:
            res = await asyncio.wait_for(
                asyncio.shield(hunt_future),
                timeout=KILLSWEEP_WALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            cancel_event.set()
            try:
                await asyncio.wait_for(asyncio.shield(hunt_future), timeout=WORKER_CLEANUP_TIMEOUT)
            except Exception:
                hunt_future.add_done_callback(_consume_task_exception)
            res = {"error": f"通杀分析超时(>{int(KILLSWEEP_WALL_TIMEOUT)}s)"}
        except asyncio.CancelledError:
            cancel_event.set()
            hunt_future.add_done_callback(_consume_task_exception)
            await self._mark_killsweep(finding_id, status="cancelled", fail_reason="cancelled",
                                       notes="通杀分析被控制面取消，未写入结果")
            async with SessionLocal() as s:
                await self._log(s, "killsweep", "cancelled",
                                "通杀分析被控制面取消，未写入结果",
                                level="warn", finding_id=finding_id)
            return
        except Exception as e:
            res = {"error": str(e)}

        if res.get("error"):
            err = str(res["error"])
            if "超时" in err:
                fail_reason = "timeout"
            elif self._is_quota_error(err):
                fail_reason = "quota"
            elif "LLM 调用失败" in err or "LLM" in err:
                fail_reason = "llm_error"
            else:
                fail_reason = "other"
            await self._mark_killsweep(finding_id, status="failed", fail_reason=fail_reason, notes=err[:2000])
            async with SessionLocal() as s:
                if self._is_quota_error(err):
                    await self._stop_task_for_quota(s, err, finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"通杀阶段检测到 LLM/API 额度不足，任务已自动停止: {err[:120]}",
                                    level="error", finding_id=finding_id)
                else:
                    await self._log(s, "killsweep", "error", f"通杀分析失败: {err}",
                                    level="warn", finding_id=finding_id)
            return

        pkey = product_key(res.get("product_name", ""), res.get("fofa_query", ""), res.get("fingerprint", ""))
        affected_table = res.get("affected_table") or []
        if res.get("verified_url") and not affected_table:
            vhost = collector.normalize_host(res["verified_url"])
            affected_table = [{
                "school": "待确认",
                "url": res["verified_url"],
                "host": vhost,
                "title": "",
                "vuln_type": finding_dict["vuln_type"],
                "vuln_title": finding_dict["title"],
                "status": "verified" if res.get("verified") else "candidate",
                "evidence": "通杀 Hunter 实打验证站点" if res.get("verified") else "通杀 Hunter 圈定候选",
                "dedup_key": hashlib.md5(
                    f"killsweep|{vhost}|{finding_dict['vuln_type'].lower()}|{finding_dict['title']}".encode()
                ).hexdigest(),
            }]
        async with SessionLocal() as session:
            row = await self._killsweep_row_for_finding(session, finding_id)
            if not row:
                row = Killsweep(
                    task_id=task_id, origin_finding_id=finding_id,
                    product_key=f"pending:{finding_id}",
                    status="analyzing",
                )
                session.add(row)
                await session.flush()
            # 产品指纹去重：同款系统已有别的完成记录则本条标 done+说明，不另插一行。
            exists = (await session.execute(
                select(Killsweep).where(
                    Killsweep.task_id == task_id,
                    Killsweep.product_key == pkey,
                    Killsweep.id != row.id,
                )
            )).scalar_one_or_none()
            row.product_name = res.get("product_name", "") or row.product_name
            row.vuln_type = finding_dict["vuln_type"]
            row.vuln_summary = finding_dict["title"]
            row.fofa_query = res.get("fofa_query", "")
            row.fingerprint = res.get("fingerprint", "")
            row.asset_count = res.get("asset_count", 0)
            row.edu_count = res.get("edu_count", 0)
            row.is_killsweep = bool(res.get("is_killsweep", False))
            row.confidence = res.get("confidence", "")
            row.verified_url = res.get("verified_url", "")
            row.verified = bool(res.get("verified", False))
            row.affected_table = affected_table
            row.updated_at = _now()
            if exists:
                row.status = "done"
                row.notes = (
                    f"同款产品已分析过，跳过：{res.get('product_name', '')}\n"
                    f"{(res.get('notes') or '').strip()}"
                ).strip()
                await session.commit()
                await self._log(session, "killsweep", "dedup",
                                f"同款产品已分析过，跳过：{res.get('product_name','')}",
                                finding_id=finding_id)
                return
            row.product_key = pkey or f"pending:{finding_id}"
            row.notes = res.get("notes", "")
            row.status = "done"
            row.progress = {
                "stage": "done",
                "label": _KILLSWEEP_STAGE_LABEL["done"],
                "pct": _KILLSWEEP_STAGE_PCT["done"],
                "ts": _now_iso(),
            }

            # 通杀闭环（最小验证）：可通杀 → 只自动入队 1 个最低单位站点证明通杀；
            # 批量通杀由人工在通杀列选择数量后触发（POST /killsweeps/{id}/enqueue）。
            enq = ""
            if res.get("is_killsweep"):
                added = await self._enqueue_killsweep_minimal(
                    session, task_id, affected_table, res.get("verified_url"), origin_host)
                if added:
                    enq = "；已入队 1 个最低单位站点验证通杀"
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                row = await self._killsweep_row_for_finding(session, finding_id)
                if not row:
                    return
                row.product_name = res.get("product_name", "") or row.product_name
                row.vuln_type = finding_dict["vuln_type"]
                row.vuln_summary = finding_dict["title"]
                row.fofa_query = res.get("fofa_query", "")
                row.fingerprint = res.get("fingerprint", "")
                row.asset_count = res.get("asset_count", 0)
                row.edu_count = res.get("edu_count", 0)
                row.is_killsweep = bool(res.get("is_killsweep", False))
                row.confidence = res.get("confidence", "")
                row.verified_url = res.get("verified_url", "")
                row.verified = bool(res.get("verified", False))
                row.affected_table = affected_table
                row.product_key = f"pending:{finding_id}"
                row.status = "done"
                row.notes = (
                    f"{(res.get('notes') or '').strip()}\n"
                    "[产品指纹与已有记录冲突，已保留本条源漏洞分析]"
                ).strip()
                row.updated_at = _now()
                # 通杀闭环（降级分支同样收口）：只入队 1 个最低单位站点验证通杀。
                if res.get("is_killsweep"):
                    await self._enqueue_killsweep_minimal(
                        session, task_id, affected_table, res.get("verified_url"), origin_host)
                await session.commit()
                await self._log(
                    session, "killsweep", "killsweep_done",
                    f"通杀分析「{res.get('product_name','')}」: "
                    f"{'可通杀' if res.get('is_killsweep') else '不可通杀'} "
                    f"(全网{res.get('asset_count',0)}/教育{res.get('edu_count',0)})"
                    "；产品指纹冲突已降级保留",
                    finding_id=finding_id, is_killsweep=res.get("is_killsweep"),
                    asset_count=res.get("asset_count", 0),
                )
                return
            await self._log(session, "killsweep", "killsweep_done",
                            f"通杀分析「{res.get('product_name','')}」: "
                            f"{'可通杀' if res.get('is_killsweep') else '不可通杀'} "
                            f"(全网{res.get('asset_count',0)}/教育{res.get('edu_count',0)}){enq}",
                            finding_id=finding_id, is_killsweep=res.get("is_killsweep"),
                            asset_count=res.get("asset_count", 0))

    async def _enqueue_killsweep_target(self, session: AsyncSession, task_id: str,
                                        url: str, origin: str) -> bool:
        """把通杀验证成功的同款站点作为新目标入队（host 去重；拉高优先级）。"""
        host = collector.normalize_host(url)
        if not host or host == collector.normalize_host(origin):
            return False
        from app.urlnorm import is_unusable_host
        if is_unusable_host(url) or is_unusable_host(host):
            return False
        if prefilter.is_sensitive_host(host) or prefilter.is_sensitive_host(url):
            return False
        exists = (await session.execute(
            select(Target).where(Target.task_id == task_id, Target.host == host)
        )).scalar_one_or_none()
        if exists:
            return False
        try:
            async with session.begin_nested():
                session.add(Target(
                    task_id=task_id, url=collector._ensure_url(host), host=host,
                    source="killsweep", status="queued", is_edu=True,
                    priority_score=120.0, priority_reason="[通杀验证] 同款系统已实证中招，重点出货",
                ))
        except IntegrityError:
            return False
        return True

    async def _enqueue_killsweep_minimal(self, session: AsyncSession, task_id: str,
                                         affected_table: list, verified_url: str, origin: str) -> int:
        """通杀闭环（最小验证）：只入队 1 个最低单位站点证明通杀。

        优先用 Hunter 实打验证成功的 verified_url；否则取 affected_table 里第一个
        verified 站点。批量通杀由人工在通杀列选择数量后触发 enqueue_killsweep_assets。
        """
        candidates: list[str] = []
        if verified_url:
            candidates.append(verified_url)
        for item in affected_table or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "") != "verified":
                continue
            url = str(item.get("url") or "").strip()
            if url and url not in candidates:
                candidates.append(url)
        enqueued = 0
        for url in candidates:
            if await self._enqueue_killsweep_target(session, task_id, url, origin):
                enqueued += 1
            if enqueued >= 1:
                break
        return enqueued

    async def enqueue_killsweep_assets(self, session: AsyncSession, task_id: str,
                                       killsweep_id: str, count: int) -> dict:
        """人工选择通杀资产数量：从 affected_table 的 verified 站点按序入队 count 个打洞。

        返回 {enqueued, skipped, remaining}；已入队过的 host 自动跳过（Target 去重）。
        """
        k = await session.get(Killsweep, killsweep_id)
        if not k or k.task_id != task_id:
            raise ValueError("通杀记录不存在")
        if not k.is_killsweep:
            raise ValueError("该记录未判定可通杀，无法批量入队")
        count = max(1, min(int(count or 0), KILLSWEEP_REPLAY_ENQUEUE_LIMIT))
        origin = k.verified_url or ""
        enqueued = 0
        skipped = 0
        for item in k.affected_table or []:
            if enqueued >= count:
                break
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "") != "verified":
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            if await self._enqueue_killsweep_target(session, task_id, url, origin):
                enqueued += 1
            else:
                skipped += 1
        k.updated_at = _now()
        await session.commit()
        remaining = max(0, len([
            it for it in (k.affected_table or [])
            if isinstance(it, dict) and str(it.get("status") or "") == "verified"
        ]) - enqueued - skipped)
        return {"enqueued": enqueued, "skipped": skipped, "remaining": remaining}

    def trigger_escalation(self, task_id: str, finding_id: str, orig_severity: str) -> bool:
        """AI accepted 后触发扩大危害深挖；finding 级 inflight 去重，单洞只打一次。"""
        if finding_id in self._escalation_inflight:
            return False
        self._escalation_inflight.add(finding_id)
        self._escalation_tasks[finding_id] = asyncio.create_task(
            self._run_escalation(task_id, finding_id, orig_severity)
        )
        return True

    async def _run_escalation(self, task_id: str, finding_id: str, orig_severity: str) -> None:
        try:
            await self._run_escalation_inner(task_id, finding_id, orig_severity)
        except Exception:
            async with SessionLocal() as s:
                await self._log(s, "escalation", "error",
                                f"扩大危害深挖异常: {traceback.format_exc()[:400]}", level="error",
                                finding_id=finding_id)
        finally:
            self._escalation_inflight.discard(finding_id)
            self._escalation_tasks.pop(finding_id, None)
            self._escalation_cancel_events.pop(finding_id, None)
            self._live_escalations.pop(finding_id, None)

    async def _run_escalation_inner(self, task_id: str, finding_id: str, orig_severity: str) -> None:
        from app.agents.escalate import EscalateHunter
        loop = asyncio.get_running_loop()

        async with SessionLocal() as session:
            f = await session.get(Finding, finding_id)
            if not f:
                return
            task = await session.get(Task, task_id)
            src_type = (task.src_type if task else "edusrc") or "edusrc"
            target_id = f.target_id
            finding_dict = {
                "title": f.title, "vuln_type": f.vuln_type, "target_url": f.target_url,
                "owner": f.owner, "description": f.description, "poc": f.poc,
                "raw_request": f.raw_request, "raw_response": f.raw_response,
                "kill_chain": f.kill_chain, "severity": orig_severity,
            }

        llm = _llm_for_task(
            await self._get_task(task_id),
            on_provider_failure=self._provider_failure_callback(
                loop, "escalation", finding_id=finding_id
            ),
        )
        cancel_event = threading.Event()
        self._escalation_cancel_events[finding_id] = cancel_event
        self._live_escalations[finding_id] = {
            "finding_id": finding_id,
            "target_id": target_id,
            "title": finding_dict.get("title") or "",
            "severity": orig_severity,
            "action": "扩大危害启动中…",
            "started_at": _now_iso(),
        }

        def emit(kind: str, data: dict):
            st = self._live_escalations.get(finding_id)
            if st is not None:
                if kind == "escalate_http":
                    st["action"] = f"HTTP {data.get('url', '')}"[:160]
                elif kind == "escalate_shell":
                    st["action"] = f"$ {data.get('command', '')}"[:160]
                elif kind == "escalate_session":
                    st["action"] = "会话态更新"
                elif kind == "escalate_done":
                    st["action"] = f"升级完成: {data.get('severity', '')}"
                elif kind == "escalate_abandon":
                    st["action"] = f"放弃: {(data.get('reason') or '')[:100]}"
                elif kind == "escalate_error":
                    st["action"] = f"异常: {(data.get('error') or '')[:100]}"
                elif kind == "escalate_start":
                    st["action"] = "扩大危害进行中…"
            asyncio.run_coroutine_threadsafe(
                bus.publish(task_id, {"agent": "escalation", "kind": kind, "finding_id": finding_id,
                                      "ts": _now_iso(), **data}),
                loop,
            )

        def do_hunt() -> dict:
            hunter = EscalateHunter(
                finding_dict, llm=llm, on_event=emit,
                src_type=src_type, cancel_event=cancel_event,
                src_rules=(task.src_rules if task else "") or "",
                guard_ops=(task.guard_ops if task else []) or [],
            )
            try:
                return hunter.run().model_dump(mode="json")
            finally:
                hunter.executor.kill_processes()

        escalate_sem = agent_semaphore("escalation")
        try:
            await asyncio.wait_for(escalate_sem.acquire(), timeout=AGENT_SEM_ACQUIRE_TIMEOUT)
        except asyncio.TimeoutError:
            async with SessionLocal() as s:
                await self._log(s, "orchestrator", "escalate_deferred",
                                f"扩大危害并发位等待超时(>{int(AGENT_SEM_ACQUIRE_TIMEOUT)}s)，稍后重试",
                                level="warn", finding_id=finding_id)
            return
        try:
            hunt_future = loop.run_in_executor(AGENT_EXECUTOR, do_hunt)
        except BaseException:
            escalate_sem.release()
            raise

        def _release_escalation(fut: asyncio.Future) -> None:
            escalate_sem.release()
            _consume_task_exception(fut)

        hunt_future.add_done_callback(_release_escalation)
        try:
            res = await asyncio.wait_for(asyncio.shield(hunt_future), timeout=ESCALATE_WALL_TIMEOUT)
        except asyncio.TimeoutError:
            cancel_event.set()
            try:
                await asyncio.wait_for(asyncio.shield(hunt_future), timeout=WORKER_CLEANUP_TIMEOUT)
            except Exception:
                hunt_future.add_done_callback(_consume_task_exception)
            res = {"escalated": False, "reason": f"扩大危害深挖超时(>{int(ESCALATE_WALL_TIMEOUT)}s)"}
        except asyncio.CancelledError:
            cancel_event.set()
            hunt_future.add_done_callback(_consume_task_exception)
            return
        except Exception as e:
            res = {"error": str(e)}

        if res.get("error"):
            async with SessionLocal() as s:
                if self._is_quota_error(str(res["error"])):
                    await self._stop_task_for_quota(s, str(res["error"]), finding_id=finding_id)
                    await self._log(s, "orchestrator", "quota_stop",
                                    f"扩大危害阶段检测到 LLM/API 额度不足，任务已自动停止: {str(res['error'])[:120]}",
                                    level="error", finding_id=finding_id)
                else:
                    await self._log(s, "escalation", "error", f"扩大危害深挖失败: {res['error']}",
                                    level="warn", finding_id=finding_id)
            return

        # 显著性门槛：不显著就丢弃，只留一条事件，不产出新 finding、不污染报告。
        if not _escalation_is_significant(orig_severity, res):
            reason = res.get("reason") or "未达到显著升级门槛（等级未提升且影响面无质变）"
            async with SessionLocal() as s:
                await self._log(s, "escalation", "escalate_skip",
                                f"扩大危害未显著，已放弃: {reason[:160]}", finding_id=finding_id)
            return

        await self._persist_escalation_finding(task_id, target_id, finding_id, orig_severity, res)

    async def _persist_escalation_finding(self, task_id: str, target_id: str, origin_finding_id: str,
                                          orig_severity: str, res: dict) -> None:
        """显著升级 → 生成一个全新 Finding（走 pending_review 审核流程，进报告）。

        原 finding 不动；新 finding 用独立 dedup_key，避免被原洞查重拦掉。
        """
        title = res.get("title") or "扩大危害升级"
        vuln_type = res.get("vuln_type") or ""
        new_severity = res.get("severity") or orig_severity
        finding_payload = {
            "description": res.get("description", ""),
            "poc": res.get("poc", ""),
            "raw_request": res.get("raw_request", ""),
            "raw_response": res.get("raw_response", ""),
            "affected_scope": res.get("affected_scope", ""),
            "kill_chain": res.get("kill_chain", []),
        }
        # Escalation 闭环收口：空发射（无任一实证）不落库，避免污染报告。
        if not escalation_guard.has_emission(res):
            async with SessionLocal() as session:
                await self._log(session, "escalation", "escalate_skip",
                                f"升级结果无实证，放弃落库（空升级洞）: {title[:80]}",
                                finding_id=origin_finding_id)
            return
        async with SessionLocal() as session:
            origin = await session.get(Finding, origin_finding_id)
            if origin is None:
                return
            base_ref = origin.target_url or origin.owner or origin_finding_id
            payload_for_key = {
                "title": title, "vuln_type": vuln_type,
                "target_url": origin.target_url, "host": origin.target_url,
            }
            # 独立 dedup_key：拼上升级标记 + 源 finding，确保不与原洞撞键。
            base_key = dedup.dedup_key(base_ref, payload_for_key)
            new_key = f"{base_key}:esc:{origin_finding_id[:8]}"
            try:
                async with session.begin_nested():
                    session.add(Finding(
                        task_id=task_id, target_id=target_id, worker_id="escalation",
                        vuln_type=vuln_type, title=title,
                        severity_claimed=new_severity,
                        target_url=origin.target_url, owner=origin.owner,
                        description=finding_payload["description"],
                        steps=[], poc=finding_payload["poc"],
                        poc_http=finding_payload.get("poc_http", "") or getattr(origin, "poc_http", ""),
                        raw_request=finding_payload["raw_request"],
                        raw_response=finding_payload["raw_response"],
                        evidence={"escalated_from": origin_finding_id, "orig_severity": orig_severity,
                                  "impact_count": int(res.get("impact_count", 0) or 0)},
                        affected_scope=finding_payload["affected_scope"],
                        kill_chain=finding_payload["kill_chain"],
                        self_check={},
                        dedup_key=new_key, status="pending_review",
                        llm_model=getattr(origin, "llm_model", "") or "",
                        llm_base_url=getattr(origin, "llm_base_url", "") or "",
                    ))
                await session.commit()
            except IntegrityError:
                # 已存在同键升级洞（重复触发/并发），跳过。
                return
            await self._log(session, "escalation", "escalate_done",
                            f"扩大危害成功「{origin.title}」→「{title}」({orig_severity}→{new_severity})，"
                            f"已生成新洞进审核",
                            finding_id=origin_finding_id, new_severity=new_severity)

    async def _get_task(self, task_id: str) -> Task:
        async with SessionLocal() as s:
            return await s.get(Task, task_id)
