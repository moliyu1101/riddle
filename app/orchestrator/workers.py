"""worker 与查重职责：worker 执行、查重历史、单站协作派生、断点上下文。"""
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


class WorkersMixin:
    def _queue_or_dead_after_attempt(self, tgt: Target, reason: str) -> bool:
        """失败/恢复后的统一回队策略。返回 True=回队，False=终态 dead。

        这类回队代表一次 worker 尝试已经失效，应消耗 retry；否则重启/僵尸回收会绕过 MAX_RETRY。
        """
        tgt.assigned_worker = ""
        tgt.heartbeat_at = None
        tgt.last_error = reason[:500]
        tgt.dead_reason = ""
        if tgt.retry_count < MAX_RETRY:
            tgt.retry_count += 1
            tgt.status = "queued"
            tgt.verdict = ""
            return True
        tgt.status = "dead"
        tgt.verdict = "error"
        tgt.dead_reason = f"{reason}，且已达重试上限"
        return False

    @staticmethod
    def _history_item(f: Finding, r: Review | None, host_key: str = "") -> dict:
        source = "finding:pending_review"
        reason = "同 host 历史已提交但尚未审核，避免跨任务重复提交同一线索"
        if r:
            if r.user_status == "rejected":
                source = "review:user_rejected"
                reason = f"人工已驳回：{(r.user_notes or r.reviewer_notes or '')[:260]}"
            elif r.user_status == "passed":
                source = "review:user_passed"
                reason = "人工已通过，已进入待提交/已提交池"
            elif r.verdict == "ignored":
                source = "review:ai_ignored"
                reason = "AI 审核已忽略：" + "；".join((r.ignore_reasons or [])[:3])
            elif r.verdict == "accepted":
                source = "review:ai_accepted"
                reason = "AI 已采纳，正在等待或已经经过人工复审"
            elif r.verdict == "deepen":
                source = "review:deepen"
                reason = f"已被打回深挖：{(r.deepen_directive or '')[:260]}"
        return {
            "id": f.id,
            "dedup_key": f.dedup_key,
            "source": source,
            "policy": "block",
            "vuln_type": f.vuln_type,
            "title": f.title,
            "target_url": f.target_url,
            "host": host_key,
            "description": (f.description or "")[:300],
            "status": f.status,
            "dedup_reason": reason,
        }

    async def _find_existing_duplicate(self, session: AsyncSession, target_ref: str, f: dict) -> dict | None:
        """落库前权威查重：全局 exact key + 同 host 软匹配。"""
        key = dedup.dedup_key(target_ref, f)
        exact = (await session.execute(
            select(Finding, Review)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .where(Finding.dedup_key == key, Finding.status != "superseded")
            .limit(1)
        )).first()
        if exact:
            old_f, old_r = exact
            return self._history_item(old_f, old_r, dedup.normalize_host(old_f.target_url or target_ref))

        host_key = dedup.normalize_host(f.get("target_url") or target_ref)
        if not host_key:
            return None
        rows = (await session.execute(
            select(Finding, Review, Target)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(Target.host == host_key, Finding.status != "superseded")
            .order_by(Finding.created_at.desc())
            .limit(100)
        )).all()
        history = [self._history_item(old_f, old_r, old_t.host or host_key) for old_f, old_r, old_t in rows]
        duplicate, matches = dedup.is_duplicate(f, history, target_ref=target_ref)
        if duplicate and matches:
            return matches[0]

        # 同一产品/同款系统可能同时存在域名站、IP站、反代别名；host 不同但产品前缀或
        # 路径 + 漏洞类型一致时，也应拦截重复产出。
        # 漏洞类型走归一化比较，但 DB 预筛用「别名集合 IN」走索引，避免全表扫：
        # 既缩小扫描范围又不漏掉库里以别名写法存储的旧记录。最终判重以 Python 侧归一化为准。
        vuln_type = dedup.normalize_vuln_type(f.get("vuln_type", ""))
        if not vuln_type:
            return None
        product = dedup.title_product_key(f.get("title", ""))
        alias_set = dedup.vuln_type_alias_set(f.get("vuln_type", ""))
        rows = (await session.execute(
            select(Finding, Review, Target)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(
                Finding.status != "superseded",
                Finding.vuln_type.in_(alias_set),
            )
            .order_by(Finding.created_at.desc())
            .limit(400)
        )).all()
        cross_history = [
            self._history_item(old_f, old_r, old_t.host or host_key)
            for old_f, old_r, old_t in rows
            if dedup.normalize_vuln_type(old_f.vuln_type) == vuln_type
            and (
                (product and dedup.title_product_key(old_f.title) == product)
                or not product  # 无产品名时交给 dedup 的跨 host 同路径兜底判定
            )
        ]
        duplicate, matches = dedup.is_duplicate(f, cross_history, target_ref=target_ref)
        return matches[0] if duplicate and matches else None

    async def _build_duplicate_history(self, session: AsyncSession, task_id: str, tgt: Target) -> list[dict]:
        """统一构建 worker 查重上下文。

        查重来源分层：
        - finding/review：跨任务同 host 历史漏洞，不管 AI 通过、人工通过、人工驳回、AI 忽略，都给 worker 看；
        - killsweep affected_table：通杀 Hunter 列出的学校/通杀洞明细，命中同 host 时也作为查重事实；
        - superseded：深挖让位的旧线索不放进强查重，避免挡住新一轮打穿后的提交。
        """
        history: list[dict] = []
        host_key = dedup.normalize_host(tgt.url or tgt.host)
        rows = (await session.execute(
            select(Finding, Review)
            .outerjoin(Review, Review.finding_id == Finding.id)
            .join(Target, Target.id == Finding.target_id)
            .where(
                Target.host == host_key,
                Finding.status != "superseded",
            )
            .order_by(Finding.created_at.desc())
            .limit(40)
        )).all()

        for f, r in rows:
            history.append(self._history_item(f, r, host_key))

        # 补充跨 host 历史：同款系统常同时存在域名/IP/反代别名，单 host 查重会漏掉
        # 「中医疫病古籍整理数据库」这类同产品重复洞，以及无产品名但同路径的别名站重复洞。
        # 用同 host 已有 finding 的归一化类型集合，DB 侧 IN 预筛走索引，避免全表扫。
        product = dedup.title_product_key(tgt.title or "")
        type_aliases: set[str] = set()
        for item in history:
            type_aliases |= dedup.vuln_type_alias_set(item.get("vuln_type", ""))
        if product or type_aliases:
            stmt = (
                select(Finding, Review, Target)
                .outerjoin(Review, Review.finding_id == Finding.id)
                .join(Target, Target.id == Finding.target_id)
                .where(Finding.status != "superseded")
            )
            # 有同 host 类型集合时按类型 IN 走索引收窄；否则退化为按产品名（仍限量）。
            if type_aliases:
                stmt = stmt.where(Finding.vuln_type.in_(type_aliases))
            product_rows = (await session.execute(
                stmt.order_by(Finding.created_at.desc()).limit(400)
            )).all()
            seen_ids = {item.get("id") for item in history}
            added = 0
            for f, r, old_t in product_rows:
                if f.id in seen_ids:
                    continue
                same_product = bool(product) and dedup.title_product_key(f.title) == product
                if not same_product:
                    continue
                history.append(self._history_item(f, r, old_t.host or host_key))
                seen_ids.add(f.id)
                added += 1
                if added >= 30:
                    break

        # 通杀明细表也进入 worker 查重上下文：命中同 host 时，拦截同学校同通杀洞重复提交。
        sweep_rows = (await session.execute(
            select(Killsweep).where(
                Killsweep.is_killsweep == True,  # noqa: E712
            ).order_by(Killsweep.created_at.desc()).limit(KILLSWEEP_DEDUP_SCAN_LIMIT)
        )).scalars().all()
        for sw in sweep_rows:
            for item in (sw.affected_table or []):
                if not isinstance(item, dict):
                    continue
                item_host = item.get("host") or dedup.normalize_host(item.get("url", ""))
                if item_host != host_key:
                    continue
                history.append({
                    "id": item.get("dedup_key", ""),
                    "dedup_key": item.get("dedup_key", ""),
                    "source": "killsweep:affected_table",
                    "policy": "block",
                    "vuln_type": item.get("vuln_type") or sw.vuln_type,
                    "title": item.get("vuln_title") or sw.vuln_summary,
                    "target_url": item.get("url") or tgt.url,
                    "host": item_host,
                    "description": (
                        f"通杀查重库：{sw.product_name}；学校/单位：{item.get('school','待确认')}；"
                        f"状态：{item.get('status','candidate')}；依据：{item.get('evidence','')}"
                    )[:500],
                    "status": f"killsweep:{item.get('status','candidate')}",
                    "dedup_reason": "通杀 Hunter 已列入学校/通杀洞明细表，避免重复提交同一通杀洞",
                })
        # 只压缩池子，不把所有历史摊进 prompt；worker prompt 里仍只展示前 6 条摘要。
        return dedup.compact_history(history, target_ref=tgt.url or tgt.host, limit=60)

    async def _build_coverage_context(self, session: AsyncSession, task_id: str, tgt: Target) -> str:
        """同站协作覆盖摘要：后续 worker 启动时避免重复测同一批 API。"""
        host_key = dedup.normalize_host(tgt.url or tgt.host)
        if not host_key:
            return ""
        rows = (await session.execute(
            select(TaskEvent)
            .where(TaskEvent.task_id == task_id, TaskEvent.kind == "coverage_reported")
            .order_by(TaskEvent.id.desc())
            .limit(80)
        )).scalars().all()
        lines: list[str] = []
        seen: set[str] = set()
        for event in rows:
            payload = event.payload or {}
            if payload.get("host") != host_key:
                continue
            route = payload.get("route") or "unknown"
            summary = (payload.get("summary") or "")[:180]
            endpoints = payload.get("endpoints") or []
            sample = []
            for item in endpoints[:6]:
                if not isinstance(item, dict):
                    continue
                method = (item.get("method") or "GET").upper()
                path = item.get("path") or item.get("url") or ""
                status = item.get("status")
                result = item.get("result") or item.get("note") or ""
                sample.append(f"{method} {path} => {status or '-'} {result}".strip())
            key = f"{route}:{summary}:{'|'.join(sample)}"
            if key in seen:
                continue
            seen.add(key)
            tail = "；".join(sample[:4])
            line = f"- {route}: {summary}"
            if tail:
                line += f"（{tail[:260]}）"
            lines.append(line)
            if len(lines) >= 12:
                break
        if not lines:
            return ""
        return "# 同站协作覆盖摘要（前序 worker 上报）\n" + "\n".join(lines) + "\n"

    @staticmethod
    def _next_site_followup_source(used: set[str]) -> str:
        for idx in range(1, 100):
            source = f"site_f{idx:02d}"
            if source not in used:
                used.add(source)
                return source
        return ""

    async def _spawn_site_followups(
        self,
        session: AsyncSession,
        task_id: str,
        tgt: Target,
        coverage_items: list[dict],
    ) -> int:
        """把前序覆盖记录转成具体 API/路径的定向追打 worker。"""
        if not site_collab.is_site_source(tgt.source):
            return 0
        # follow-up 自己也会上报 coverage，避免无限派生。
        if (tgt.source or "").startswith("site_f"):
            return 0
        base_url = tgt.url or (f"https://{_bracket_ipv6_host(tgt.host)}" if tgt.host else "")
        specs = site_collab.followup_specs_from_coverage(coverage_items, base_url=base_url, max_specs=8)
        if not specs:
            return 0

        added = 0
        existing_reasons = (await session.execute(
            select(Target.source, Target.priority_reason).where(Target.task_id == task_id, Target.host == tgt.host)
        )).all()
        used_sources = {str(r[0] or "") for r in existing_reasons}
        reason_pool = {str(r[1] or "") for r in existing_reasons}
        for spec in specs:
            reason = str(spec.get("reason") or "")[:300]
            if not reason or reason in reason_pool:
                continue
            source = self._next_site_followup_source(used_sources)
            if not source:
                break
            path = str(spec.get("path") or "").strip()
            follow_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) if path else base_url
            try:
                async with session.begin_nested():
                    session.add(Target(
                        task_id=task_id,
                        url=follow_url or base_url,
                        host=tgt.host,
                        source=source,
                        status="queued",
                        priority_score=float(spec.get("priority") or site_collab.FOCUSED_ROUTE.priority),
                        priority_reason=reason,
                    ))
            except IntegrityError:
                # 并发：两条 discovery worker 同时派生撞了同一 site_f 编号，跳过，
                # 不让唯一索引冲突在外层 commit 时炸掉整次 persist。
                continue
            reason_pool.add(reason)
            added += 1
        return added

    async def _spawn_site_theme_routes(
        self,
        session: AsyncSession,
        task_id: str,
        tgt: Target,
    ) -> int:
        """discovery 侦察路线(map/js)完成后，自动派发 5 条主题深挖路线。

        单站协作的真正分工在这里落地：先由 site_map/site_js 摸清入口与 JS/API，
        再由 认证越权 / 未授权配置 / 文件 / 注入RCE / 业务逻辑 五条主题路线分头深挖，
        每条主题 worker 派发时都会带上前序侦察的 coverage 上下文（见 _run_worker_inner）。

        - 仅在 discovery 路线(phase==0)完成后触发；
        - 每个 host 只派一次（靠 source 存在性去重 + 唯一索引 + savepoint 兜并发）；
        - 主题路线本身不会再触发本函数（phase>0）。
        """
        route = site_collab.route_for_source(tgt.source or "")
        if not route or route.phase != 0:
            return 0
        existing = (await session.execute(
            select(Target.source).where(Target.task_id == task_id, Target.host == tgt.host)
        )).all()
        existing_sources = {str(r[0] or "") for r in existing}
        added = 0
        for troute in site_collab.FOLLOWUP_ROUTES:
            if troute.source in existing_sources:
                continue
            try:
                async with session.begin_nested():
                    session.add(Target(
                        task_id=task_id,
                        url=tgt.url,
                        host=tgt.host,
                        source=troute.source,
                        status="queued",
                        priority_score=troute.priority,
                        priority_reason=site_collab.route_reason(troute),
                    ))
            except IntegrityError:
                # 并发：另一条 discovery worker 已派过同款主题路线，跳过。
                continue
            existing_sources.add(troute.source)
            added += 1
        return added

    async def _run_worker(self, task_id: str, target_id: str, url: str,
                          cancel_event: threading.Event) -> None:
        """worker 协程顶层守卫：确保任何未预期异常都被记录+落地，
        绝不让 worker「莫名其妙消失」(协程异常死亡 → _reap 静默吞掉 → 目标虚挂 scanning)。"""
        try:
            await self._run_worker_inner(task_id, target_id, url, cancel_event)
        except asyncio.CancelledError:
            # 正常取消(pause/stop/reclaim)：清理活态，目标回队由 cancel/reclaim 链路接管。
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            self._worker_cancel_events.pop(target_id, None)
            self._schedule_prune_target_traces(task_id, target_id)
            raise
        except Exception as e:
            # 关键兜底：setup 阶段(建上下文/查重/取LLM/信号量)或任何未捕获异常，
            # 都在这里兜住——记后端日志 + 写事件流 + 给目标一个 error 终态，
            # 而不是让协程静默死亡、目标永远虚挂 scanning 直到被 reclaim 回队空转。
            summary = self._summarize_exc(e)
            host_hint = (url or "").split("://")[-1].rstrip("/")[:60]
            logger.warning(
                "TaskRunner[%s] worker crashed target=%s host=%s:\n%s",
                self.task_id, target_id[:8], host_hint, traceback.format_exc(),
            )
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            self._worker_cancel_events.pop(target_id, None)
            try:
                async with SessionLocal() as s:
                    await self._log(s, "worker", "error",
                                    f"worker 异常退出（{host_hint}）：{summary}",
                                    level="error", target_id=target_id)
            except Exception:
                pass
            try:
                await self._persist_worker_result(
                    task_id, target_id,
                    {"verdict": "error", "findings": [], "error": summary},
                )
            except Exception:
                logger.warning("TaskRunner[%s] worker crash persist failed target=%s",
                               self.task_id, target_id[:8])
            self._schedule_prune_target_traces(task_id, target_id)

    async def _run_worker_inner(self, task_id: str, target_id: str, url: str,
                                cancel_event: threading.Event) -> None:
        loop = asyncio.get_running_loop()
        host = url.split("://")[-1].rstrip("/")
        started_monotonic = loop.time()
        self._worker_last_activity[target_id] = started_monotonic
        self._live[target_id] = {
            "target_id": target_id, "host": host, "url": url,
            "round": 0, "action": "启动中…", "findings": 0,
            "started_at": _now_iso(),
            "last_activity_at": _now_iso(),
        }

        def _update_live(kind: str, data: dict):
            st = self._live.get(target_id)
            if not st:
                return
            self._worker_last_activity[target_id] = loop.time()
            st["last_activity_at"] = _now_iso()
            if "round" in data:
                st["round"] = data["round"]
            if data.get("model"):
                st["model"] = data["model"]
            if data.get("base_url"):
                st["model_base_url"] = data["base_url"]
            if data.get("model_role"):
                st["model_role"] = data["model_role"]
            if kind == "tool_http":
                st["action"] = f"HTTP {data.get('method','GET')} {data.get('url','')}"
            elif kind == "tool_shell":
                st["action"] = f"$ {data.get('command','')}"
            elif kind == "tool_shell_blocked":
                st["action"] = f"拦截低价值命令: {data.get('reason','')}"
            elif kind == "tool_arg_error":
                st["action"] = f"工具参数错误: {data.get('tool','')}"
            elif kind == "tool_exception":
                st["action"] = f"工具异常: {data.get('tool','')}"
            elif kind == "tool_credential_brute":
                st["action"] = f"弱口令验证: {data.get('login_url','')[:120]} ({data.get('username','')})"
            elif kind == "tool_login_session":
                st["action"] = f"登录态自动化: {data.get('login_url','')[:120]} ({data.get('username','')})"
            elif kind == "tool_login_form_scan":
                st["action"] = f"登录入口侦察: {data.get('url','')[:120]}"
            elif kind == "tool_http_batch":
                st["action"] = f"批量遍历: {data.get('url','')[:100]} ({data.get('range','')})"
            elif kind == "tool_diff_response":
                st["action"] = f"参数差异对比: {data.get('url','')[:120]}"
            elif kind == "tool_timing_probe":
                st["action"] = f"时序测量: {data.get('url','')[:120]}"
            elif kind == "tool_crawl_links":
                st["action"] = f"攻击面抓取: {data.get('url','')[:120]}"
            elif kind == "tool_sqli_probe":
                st["action"] = f"SQL注入探测: {data.get('url','')[:100]} ({data.get('param_name','')})"
            elif kind == "tool_upload_probe":
                st["action"] = f"上传接口探测: {data.get('url','')[:120]}"
            elif kind == "tool_access_boundary":
                st["action"] = f"权限边界测试: {data.get('url','')[:120]}"
            elif kind == "tool_capture_evidence":
                st["action"] = f"存证快照: {data.get('url','')[:120]}"
            elif kind == "tool_verify_known_vuln":
                st["action"] = f"指纹漏洞实测: {data.get('vuln_name','')[:60]} @ {data.get('url','')[:80]}"
            elif kind == "tool_update_cognition":
                st["action"] = f"认知更新 [{data.get('slot','')}]: {data.get('text','')[:60]}"
            elif kind == "worker_reflect":
                st["action"] = "🔄 周期复盘"
            elif kind == "tool_asset_discovery":
                st["action"] = f"资产发现: {data.get('target','')[:120]} ({data.get('enum_type','path')})"
            elif kind == "tool_fingerprint":
                st["action"] = f"指纹识别: {data.get('url','')[:120]}"
            elif kind == "worker_thought":
                st["action"] = "💭 " + (data.get("text") or "")[:120]
            elif kind == "worker_directive":
                st["action"] = "🎛 执行人工指令: " + (data.get("text") or "")[:100]
            elif kind == "llm_round_start":
                st["action"] = "LLM 思考中…"
            elif kind == "llm_error":
                st["action"] = f"LLM 异常: {data.get('error','')}"
            elif kind == "worker_auto_finish":
                st["action"] = f"自动收敛: {data.get('summary','')}"
            elif kind == "finding_submitted":
                st["findings"] = st.get("findings", 0) + 1
                st["action"] = f"🎯 发现漏洞: {data.get('title','')}"
            elif kind == "duplicate_checked":
                st["action"] = (
                    f"查重: {'重复' if data.get('duplicate') else '未重复'} "
                    f"{data.get('title','')}"
                )
            elif kind == "finding_duplicate":
                st["action"] = f"重复漏洞已拦截: {data.get('title','')}"
            elif kind == "intel_reported":
                st["action"] = f"记录情报: {data.get('intel_kind','')}"
            elif kind == "blackboard_publish":
                st["action"] = f"黑板共享: [{data.get('key','')}] {data.get('value','')[:60]}"
            elif kind == "blackboard_declare":
                st["action"] = f"黑板分工: {data.get('direction','')[:60]}"
            elif kind == "worker_finish":
                st["action"] = f"收尾: {data.get('verdict','')}"
            elif kind == "auth_status":
                st["auth"] = data.get("status") or ""
                st["auth_kinds"] = ",".join(data.get("kinds") or [])
                st["auth_label"] = (data.get("reason") or data.get("message") or "")[:160]
                st["action"] = data.get("message") or f"凭据: {data.get('status')}"

        def emit(kind: str, data: dict):
            if cancel_event.is_set():
                return
            # 线程内回调 → 投递到事件循环（更新活态 + 推送看板）
            def _do():
                if cancel_event.is_set():
                    return
                try:
                    payload = {
                        **(data or {}),
                        **self._llm_payload(llm, "挖掘模型"),
                    }
                    # finding_submitted 携带完整 finding：实时落库（不丢洞），并从看板推送里剥离大字段。
                    finding_payload = payload.pop("finding", None) if kind == "finding_submitted" else None
                    if finding_payload:
                        # submit 当下的 selected_provider 写入洞记录，端点池切换后仍可追溯
                        llm_meta = self._llm_payload(llm, "挖掘模型")
                        finding_payload = {
                            **finding_payload,
                            "_llm_model": llm_meta.get("model") or "",
                            "_llm_base_url": llm_meta.get("base_url") or "",
                        }
                        ft = asyncio.create_task(
                            self._persist_single_finding(task_id, target_id, finding_payload)
                        )
                        # 观测异常：finding 实时落库失败必须留痕，否则真洞可能静默丢失。
                        ft.add_done_callback(lambda f: _log_bg_task_exc(f, "persist_single_finding"))
                    if kind == "auth_status":
                        at = asyncio.create_task(self._persist_auth_status(target_id, dict(payload)))
                        at.add_done_callback(lambda f: _log_bg_task_exc(f, "persist_auth_status"))
                    if kind in _WORKER_TRACE_KINDS:
                        self._persist_worker_trace(task_id, target_id, kind, dict(payload))
                    _update_live(kind, payload)
                    pt = asyncio.create_task(bus.publish(
                        task_id, {"agent": "worker", "kind": kind, "target_id": target_id,
                                  "ts": _now_iso(), **payload}))
                    pt.add_done_callback(lambda f: _log_bg_task_exc(f, "bus.publish"))
                except Exception:
                    logger.warning("TaskRunner[%s] emit dispatch failed target=%s kind=%s",
                                   self.task_id, target_id[:8], kind, exc_info=True)
            loop.call_soon_threadsafe(_do)

        deepen_context = None
        target_meta: dict = {}
        duplicate_history: list[dict] = []
        src_type = "edusrc"
        src_rules = ""
        guard_ops: list[str] = []
        fofa_key = ""
        fofa_base_url = ""
        engine_name = "fofa"
        blackboard = None
        async with SessionLocal() as session:
            tgt = await session.get(Target, target_id)
            task_obj = await session.get(Task, task_id)
            if task_obj:
                src_type = task_obj.src_type or "edusrc"
                src_rules = task_obj.src_rules or ""
                guard_ops = task_obj.guard_ops or []
                engine_cfg = resolve_engine_config(task_obj)
                engine_name = engine_cfg["engine"]
                fofa_key = engine_cfg["key"]
                fofa_base_url = engine_cfg["base_url"]
            if tgt:
                tgt.status = "scanning"
                self._live[target_id]["score"] = tgt.priority_score
                self._live[target_id]["score_reason"] = tgt.priority_reason
                deepen_context = tgt.deepen_context or None
                # 资产情报：候选归属学校/org/title，供 worker 核实并写进报告 owner
                target_meta = {
                    "school": tgt.school or "", "org": tgt.org or "",
                    "title": tgt.title or "", "is_edu": tgt.is_edu,
                    "source": tgt.source or "", "priority_reason": tgt.priority_reason or "",
                    "leaked_creds": tgt.leaked_creds or [],
                    "auth_context": tgt.auth_context or None,
                    "user_auth": tgt.auth_context or None,
                }
                if tgt.auth_status:
                    _as = tgt.auth_status or {}
                    self._live[target_id]["auth"] = _as.get("status") or ""
                    self._live[target_id]["auth_label"] = _as.get("reason") or ""
                    # 种类一并回填（前端徽章「Cookie·已注入」需要）；老数据无 kinds 则留空
                    self._live[target_id]["auth_kinds"] = ",".join(_as.get("kinds") or [])
                # 业务上下文画像：按站点标题/归属/来源推断业务类型，引导 worker 按业务逻辑挖。
                biz = None
                try:
                    biz = profile_business(
                        url=tgt.url or url,
                        title=tgt.title or "",
                        org=tgt.org or "",
                        school=tgt.school or "",
                        priority_reason=tgt.priority_reason or "",
                        src_type=src_type,
                    )
                    if biz:
                        target_meta["business_profile"] = biz.as_dict()
                        target_meta["business_block"] = render_business_block(biz)
                        self._live[target_id]["biz"] = biz.label
                except Exception:
                    pass
                try:
                    plan = playbook_router.route_target(
                        url=tgt.url or url,
                        title=tgt.title or "",
                        priority_reason=tgt.priority_reason or "",
                        src_type=src_type,
                        source=tgt.source or "",
                        deepen_context=deepen_context,
                        leaked_creds=tgt.leaked_creds or [],
                        business_id=biz.biz_id if biz else "",
                    )
                    target_meta["playbook_route"] = plan.as_dict()
                    target_meta["playbook_block"] = playbook_router.render_playbook_block(plan)
                    self._live[target_id]["playbook"] = plan.label
                except Exception:
                    pass
                # 差异化策略：大众洞规避 + 差异化重点，注入 worker 引导挖别人挖不到的洞。
                try:
                    target_meta["diff_block"] = diff_strategy_block(
                        business_id=biz.biz_id if biz else "",
                        business_label=biz.label if biz else "",
                        playbook_route_id=(target_meta.get("playbook_route") or {}).get("route_id") or "",
                    )
                except Exception:
                    pass
                # 业务状态机引导：多步业务流绕过测试手法，业务逻辑洞的差异化来源。
                try:
                    target_meta["state_machine_block"] = render_state_machine_block(
                        business_id=biz.biz_id if biz else "",
                        title=tgt.title or "",
                        description=tgt.priority_reason or "",
                        url=tgt.url or url,
                        priority_reason=tgt.priority_reason or "",
                    )
                except Exception:
                    pass
                # 业务逻辑测试模板：按业务类型给结构化可执行清单（通用+专属用例），
                # 把业务逻辑测试从 LLM 自主发挥升级为 checklist 式逐条实测。
                try:
                    target_meta["biz_test_block"] = render_biz_test_block(
                        business_id=biz.biz_id if biz else "",
                        business_label=biz.label if biz else "",
                    )
                except Exception:
                    pass
                # 触发式检索全局情报库：按 root 域 + 系统指纹命中才注入（不冗余）。
                try:
                    root = target_cluster.root_domain(tgt.host or "")
                    fps = intel_lib.detect_fingerprints(tgt.host or "", tgt.title or "", tgt.org or "")
                    hits = await intel_lib.lookup_intel(session, root, fps)
                    block = intel_lib.render_intel_block(hits)
                    if block:
                        target_meta["intel_block"] = block
                except Exception:
                    pass
                # 挖洞知识库：按任务漏洞类型 + 目标特征命中相关手册/方法论，限量注入。
                try:
                    from app.agents.knowledge import lookup_kb, render_kb_block
                    _vtypes = (task_obj.vuln_types or []) if task_obj else []
                    _qtext = f"{tgt.title or ''} {tgt.org or ''} {tgt.priority_reason or ''}"
                    _kbits = await lookup_kb(session, query_terms=_vtypes, query_text=_qtext)
                    _kb = render_kb_block(_kbits)
                    if _kb:
                        target_meta["knowledge_block"] = _kb
                except Exception:
                    pass
                try:
                    route = site_collab.route_for_source(tgt.source or "")
                    if route:
                        coverage_block = await self._build_coverage_context(session, task_id, tgt)
                        target_meta["site_collab_route"] = {
                            "source": route.source,
                            "label": route.label,
                            "focus": route.focus,
                            "js_first": route.js_first,
                        }
                        target_meta["site_collab_block"] = site_collab.render_context(
                            route,
                            site_info=(task_obj.fofa_query if task_obj else ""),
                            coverage_block=coverage_block,
                            focus_note=tgt.priority_reason or "",
                            skip_recon=site_collab.skip_recon_enabled(task_obj) if task_obj else False,
                        )
                        # 单站协作：启用任务级黑板，供同站多 worker 实时共享信息、错开路线。
                        blackboard = self._get_blackboard()
                        self._live[target_id]["mode"] = "site"
                        self._live[target_id]["playbook"] = route.label
                        self._live[target_id]["action"] = f"协作路线：{route.label}"
                except Exception:
                    pass
                if deepen_context:
                    self._live[target_id]["mode"] = "deepen"
                    self._live[target_id]["action"] = "🔁 定向深挖启动中…"
                duplicate_history = await self._build_duplicate_history(session, task_id, tgt)
                await session.commit()
            if not tgt:
                # 目标已被删除（任务删除级联 delete-orphan）：不再建 LLM 客户端/起线程
                # 空跑整轮——结果无处落库，还白烧 token 与目标流量。
                self._live.pop(target_id, None)
                self._worker_last_activity.pop(target_id, None)
                logger.info(
                    "[worker_skip] target=%s 已不存在（任务/目标被删除），跳过本次派发", target_id[:8]
                )
                return
            llm = _llm_for_task(
                task_obj,
                on_provider_failure=self._provider_failure_callback(
                    loop, "worker", target_id=target_id
                ),
                on_provider_selected=self._provider_selected_callback(
                    loop, target_id, "挖掘模型"
                ),
            )
            self._live[target_id].update(self._llm_payload(llm, "挖掘模型"))
            prompt_version = resolve_worker_prompt_version(task_obj)

        worker_holder: dict[str, Worker] = {}

        def do_work() -> dict:
            worker = Worker(url, llm=llm, on_event=emit,
                            deepen_context=deepen_context, target_meta=target_meta,
                            duplicate_history=duplicate_history,
                            cancel_event=cancel_event, src_type=src_type,
                            fofa_key=fofa_key, fofa_base_url=fofa_base_url,
                            engine=engine_name,
                            prompt_version=prompt_version,
                            src_rules=src_rules,
                            guard_ops=guard_ops,
                            pop_directive=lambda: self._pop_directive(target_id),
                            blackboard=blackboard, worker_id=target_id)
            worker_holder["worker"] = worker
            try:
                return worker.run().model_dump(mode="json")
            finally:
                # 正常完成的清理：只杀残留子进程，绝不 set cancel_event。
                # （历史事故根因：这里曾调 cancel_running() 顺带 set 了 cancel_event，
                #  导致每个正常完成的 worker 都被下方 externally_cancelled 判定误判为"被取消"而丢弃结果，
                #  findings/done 永远为 0、出洞概率暴跌。）
                worker.executor.kill_processes()
                with self._worker_directive_lock:
                    self._worker_directives.pop(target_id, None)

        cancelled = False
        # 区分「超时」与「外部取消(pause/stop/reclaim)」：两者都会 set cancel_event(通知
        # 还在跑的 worker 线程停手)，但超时应当走正常 persist 落 timeout verdict(触发重试/dead
        # 状态机)，而外部取消才丢弃结果由回队逻辑接管。用独立标志把两者分开。
        is_timeout = False
        result: dict | None = None
        # 并发信号量：worker 实际并发由此封顶，保证不会占满 AGENT_EXECUTOR 把
        # reviewer/killsweep/assistant 饿死。信号量在 future 真正结束(含超时后线程
        # 仍在跑的情况)时才释放，避免线程未退就放行新 worker 导致池子超订。
        worker_sem = agent_semaphore("worker")
        # acquire 本身可能被取消(pause/stop)——此时还没建 heartbeat/future，无需清理。
        # 并发位超时保护：幽灵线程占位时 acquire 会无限等待，worker 会永久挂在
        # 「启动中…」且没有心跳/超时兜底（历史现象：配了并发却只有 1 个在跑）。
        # 等不到位就把目标回队列、退出本协程，由下一轮 tick 重新派发。
        try:
            await asyncio.wait_for(worker_sem.acquire(), timeout=WORKER_SEM_ACQUIRE_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(
                "[sem_wait] target=%s 等待 worker 并发位超时(%.0fs)，目标回队待重派，活跃协程=%d",
                target_id[:8], WORKER_SEM_ACQUIRE_TIMEOUT, len(self._active_workers),
            )
            self._live.pop(target_id, None)
            self._worker_last_activity.pop(target_id, None)
            async with SessionLocal() as s2:
                tgt = await s2.get(Target, target_id)
                if tgt is not None and tgt.status == "scanning":
                    tgt.status = "queued"
                    tgt.assigned_worker = ""
                    tgt.heartbeat_at = None
                    tgt.last_error = f"等待 worker 并发位超时({WORKER_SEM_ACQUIRE_TIMEOUT:.0f}s)，已回队"
                    await s2.commit()
            return
        # 心跳放在拿到并发位之后再起：确保它的生命周期与 worker_future 完全对齐，
        # 任何一条退出路径都能在下方 finally 里把它取消，杜绝心跳协程泄漏。
        heartbeat_task = asyncio.create_task(self._heartbeat_target(target_id))
        # 关键防泄漏：拿到信号量后，只要 future 没能挂上「结束即释放」的回调，
        # 就必须在这里立即把信号量还回去。否则 run_in_executor 一旦抛错(如池已
        # 关闭 RuntimeError)，这个并发位就永久丢失——攒够 8 个后 worker 永远
        # 起不来、后续所有 worker 静默卡死在 acquire()（"莫名其妙都不挖了"）。
        try:
            worker_future = loop.run_in_executor(AGENT_EXECUTOR, do_work)
        except BaseException:
            worker_sem.release()
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await heartbeat_task
            raise
        # 幂等释放：future 正常完成释放一次；若线程卡死（future 永不完成），由下方
        # 超时/取消路径强制释放一次，未来线程真返回时不会重复释放导致超订。
        _sem_released = False

        def _release_sem(_f: object = None) -> None:
            nonlocal _sem_released
            if not _sem_released:
                _sem_released = True
                worker_sem.release()

        worker_future.add_done_callback(_release_sem)
        try:
            # 活跃续命：worker 有持续事件就不因旧的 30min 墙钟被误杀；
            # 真正卡死则按 idle timeout 回收，活跃过久也有 max wall 兜底。
            while True:
                try:
                    poll_limit = WORKER_IDLE_TIMEOUT if WORKER_IDLE_TIMEOUT > 0 else WORKER_WAIT_POLL_INTERVAL
                    poll = max(1.0, min(WORKER_WAIT_POLL_INTERVAL, poll_limit))
                    result = await asyncio.wait_for(asyncio.shield(worker_future), timeout=poll)
                    break
                except asyncio.TimeoutError:
                    now = loop.time()
                    reason = _worker_timeout_reason(
                        started_monotonic,
                        self._worker_last_activity.get(target_id, started_monotonic),
                        now,
                    )
                    if not reason:
                        continue
                    raise asyncio.TimeoutError(reason)
        except asyncio.TimeoutError as e:
            timeout_reason = str(e) or "worker 超时"
            logger.warning(
                "[cancel_set] TimeoutError target=%s idle=%s max_wall=%s reason=%s",
                target_id[:8], WORKER_IDLE_TIMEOUT, WORKER_MAX_WALL_TIMEOUT, timeout_reason,
            )
            cancel_event.set()
            is_timeout = True
            worker = worker_holder.get("worker")
            if worker:
                worker.executor.cancel_running()
            result = {"verdict": "timeout", "findings": [], "error": timeout_reason}
            try:
                cleaned = await asyncio.wait_for(asyncio.shield(worker_future), timeout=WORKER_CLEANUP_TIMEOUT)
                # 超时回收后仍要保住已出洞 + 进度快照，避免「挖了一半全丢」
                if isinstance(cleaned, dict):
                    if cleaned.get("findings"):
                        result["findings"] = cleaned.get("findings") or []
                    if cleaned.get("resume_context"):
                        result["resume_context"] = cleaned.get("resume_context") or {}
            except Exception:
                worker_future.add_done_callback(_consume_task_exception)
                # 线程仍卡死未返回：强制释放并发位，防止幽灵线程永久占位
                # （线程真返回时 _release_sem 幂等，不会重复释放）。
                _release_sem()
            async with SessionLocal() as s:
                await self._log(s, "worker", "timeout",
                                f"目标超时强制回收：{timeout_reason}，已触发工具子进程清理",
                                level="warn", target_id=target_id)
        except asyncio.CancelledError:
            logger.warning("[cancel_set] CancelledError target=%s", target_id[:8])
            cancelled = True
            cancel_event.set()
            worker = worker_holder.get("worker")
            if worker:
                worker.executor.cancel_running()
            worker_future.add_done_callback(_consume_task_exception)
            _release_sem()
        except Exception as e:
            result = {"verdict": "error", "findings": [], "error": str(e)}
        finally:
            heartbeat_task.cancel()
            # 吞掉一切：心跳可能早已因瞬时异常死亡，绝不能让它的残留异常在这里
            # 把一次本已拿到结果的 worker 连累成 error（历史坑：finally 里 await
            # 一个已异常结束的 task 会把该异常重新抛出）。
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await heartbeat_task

        live_snapshot = dict(self._live.get(target_id) or {})
        self._live.pop(target_id, None)
        self._worker_last_activity.pop(target_id, None)
        self._worker_cancel_events.pop(target_id, None)
        # 丢弃仅针对「外部取消」(pause/stop/reclaim)：这些路径已由回队逻辑接管目标状态。
        # 超时(is_timeout)虽然也 set 了 cancel_event，但要正常走 persist 落 timeout verdict，
        # 触发 _persist_worker_result 里的 timeout 重试/dead 分支，而不是被丢弃后靠 reclaim 兜底。
        externally_cancelled = cancelled or target_id in self._cancelled_targets or (
            cancel_event.is_set() and not is_timeout
        )
        if externally_cancelled:
            # 诊断：worker 结果被丢弃的真实原因（定位"挖了没落库"的关键路径）。
            n_find = len((result or {}).get("findings") or [])
            logger.warning(
                "[worker_discard] target=%s cancelled=%s cancel_event=%s in_cancelled_set=%s findings=%d verdict=%s",
                target_id[:8], cancelled, cancel_event.is_set(),
                target_id in self._cancelled_targets, n_find,
                (result or {}).get("verdict"),
            )
            self._cancelled_targets.discard(target_id)
            # 被取消（pause/stop/超时/reclaim）时，目标状态变更丢弃由回队逻辑接管；
            # 但 worker 若已经打出实锤 findings，绝不能跟着一起扔——洞是真金白银，
            # 这里单独把已发现的 findings 落库（幂等去重），避免"挖出洞却没入库"。
            salvage = (result or {}).get("findings") or []
            if salvage:
                try:
                    await self._salvage_findings(task_id, target_id, salvage)
                except Exception:
                    pass
            self._schedule_prune_target_traces(task_id, target_id)
            return
        final_result = result or {"verdict": "error", "findings": []}
        final_result.setdefault("_runtime", {})
        final_result["_runtime"].update({
            "started_at": live_snapshot.get("started_at"),
            "finished_at": _now_iso(),
            "duration_seconds": max(0.0, loop.time() - started_monotonic),
            "model": live_snapshot.get("model") or "",
            "base_url": live_snapshot.get("model_base_url") or live_snapshot.get("base_url") or "",
            "model_role": live_snapshot.get("model_role") or "挖掘模型",
        })
        await self._persist_worker_result(task_id, target_id, final_result)
        self._schedule_prune_target_traces(task_id, target_id)

    async def _revive_deepen_origin(self, session: AsyncSession, tgt: Target) -> str | None:
        """深挖回炉走到终态(dead)且本轮未产出可替代的新 finding 时，把原始被 superseded 的
        finding 复位为可人工复审。仅处理 AI/人工深挖来源(deepen_context 带 from_finding_id)；
        worker_lead 自动深挖无前身 finding，不涉及。返回被复活的 finding_id 或 None。"""
        dctx = tgt.deepen_context or {}
        origin_fid = (dctx.get("from_finding_id") or "").strip()
        origin_src = (dctx.get("source") or "").strip()
        if not origin_fid or origin_src not in ("ai", "user"):
            return None
        origin = await session.get(Finding, origin_fid)
        if origin is None or origin.status != "superseded":
            return None
        # superseded→reviewed：落进「AI 未采纳」归档(深挖未果·置顶)，可一键恢复到复审队列
        origin.status = "reviewed"
        orv = (await session.execute(
            select(Review).where(Review.finding_id == origin_fid)
        )).scalar_one_or_none()
        if orv is not None:
            orv.reviewer_notes = (
                (orv.reviewer_notes or "").rstrip()
                + "\n[系统] 深挖回炉未升级，已复位原线索为可人工复审（深挖未果，疑似好洞）。"
            ).strip()
        return origin_fid

    @staticmethod
    def _apply_resume_context(tgt: Target, result: dict) -> None:
        """LLM 中断回队时，把 worker 进度快照写入 deepen_context，下一轮续挖。"""
        resume = result.get("resume_context") if isinstance(result.get("resume_context"), dict) else {}
        if not resume:
            return
        prev = dict(tgt.deepen_context or {})
        cookies = resume.get("session_cookies") if isinstance(resume.get("session_cookies"), dict) else {}
        headers = resume.get("session_headers") if isinstance(resume.get("session_headers"), dict) else {}
        notes = str(resume.get("worker_notes") or "")[:4000]
        probed = [u for u in (resume.get("probed_urls") or []) if isinstance(u, str) and u.strip()][:120]
        directive = str(
            resume.get("directive")
            or prev.get("directive")
            or "上一轮因 LLM 中断，请从工作笔记与会话态继续，不要从头泛扫。"
        )[:2000]
        tgt.deepen_context = {
            "directive": directive,
            "vuln_type": prev.get("vuln_type") or "",
            "original_title": prev.get("original_title") or "LLM中断续挖",
            "original_summary": str(
                resume.get("original_summary") or notes or prev.get("original_summary") or ""
            )[:1000],
            "from_finding_id": prev.get("from_finding_id") or "",
            "source": "llm_interrupt",
            "worker_notes": notes,
            "session_cookies": cookies,
            "session_headers": headers,
            "probed_urls": probed,
            "shell_cwd": str(resume.get("shell_cwd") or ""),
            "shell_env": resume.get("shell_env") if isinstance(resume.get("shell_env"), dict) else {},
            "shell_history": resume.get("shell_history") if isinstance(resume.get("shell_history"), list) else [],
            "rounds_done": int(resume.get("rounds_done") or 0),
        }
