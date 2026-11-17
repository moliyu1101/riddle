"""Part 3 协同工作流与深化重测测试：Escalate 会话认知继承 / 多目标黑板协同 / 硬骨头唤醒 API。"""
from __future__ import annotations

import concurrent.futures
import threading
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.escalate import EscalateHunter, load_session_heritage
from app.agents.worker import Worker
from app.api import tasks as tasks_api
from app.config import worker_config
from app.db.models import Base, Intel, Target, Task
from app.orchestrator.runner import TaskRunner


class SessionHeritageTest(unittest.TestCase):
    def test_worker_writes_session_heritage_and_escalate_inherits_and_renders_brief(self):
        with tempfile.TemporaryDirectory() as tmp:
            orig_root = worker_config.work_root
            try:
                worker_config.work_root = Path(tmp)
                dummy_llm = SimpleNamespace(chat=lambda *a, **kw: None)
                worker = Worker(
                    "https://portal.example.edu.cn/login",
                    llm=dummy_llm,
                )
                worker.executor.session_set(
                    cookies={"JSESSIONID": "sid_heritage_99"},
                    headers={"X-Auth-Token": "tok_heritage_1"},
                )
                worker.executor.update_notes("发现 /api/v1/user 存在越权读取，且管理员接口依赖 X-Auth-Token。")
                worker.executor.update_cognition(slot="confirmed", text="/api/v1/user 返回全校学生信息")
                worker.executor.update_cognition(slot="excluded", text="/static 仅静态资源")
                worker.executor.update_cognition(slot="leads", text="/api/admin/export_all 尚未探测")
                worker.executor.update_cognition(slot="plan", text="带凭证探测管理员导出接口")
                worker.findings.append({"title": "用户信息越权"})
                worker._write_session_heritage()

                heritage_path = worker.executor.work_dir / "session_heritage.json"
                self.assertTrue(heritage_path.exists())

                hunter = EscalateHunter(
                    {
                        "title": "用户信息越权",
                        "vuln_type": "越权访问",
                        "severity": "medium",
                        "target_url": "https://portal.example.edu.cn/api/v1/user",
                        "target_base_url": "https://portal.example.edu.cn/login",
                        "host": "portal.example.edu.cn",
                        "owner": "示例高校",
                    },
                    llm=dummy_llm,
                )
                brief = hunter._brief()
                self.assertEqual(hunter.executor._session_cookies.get("JSESSIONID"), "sid_heritage_99")
                self.assertEqual(hunter.executor._session_headers.get("X-Auth-Token"), "tok_heritage_1")
                self.assertIn("/api/v1/user 返回全校学生信息", hunter.executor._cognition["confirmed"])
                self.assertIn("继承的前序 Worker 会话与认知资产", brief)
                self.assertIn("/api/admin/export_all 尚未探测", brief)
                self.assertIn("发现 /api/v1/user 存在越权读取", brief)
            finally:
                worker_config.work_root = orig_root

    def test_load_session_heritage_origin_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = "https://sub.test.edu.cn"
            safe = "".join(c if c.isalnum() else "_" for c in target)[:60]
            p = Path(tmp) / safe / "session_heritage.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('{"session_cookies": {"sid": "abc"}}', encoding="utf-8")

            loaded = load_session_heritage({"target_url": "https://sub.test.edu.cn/deep/endpoint"}, work_dir=tmp)
            self.assertEqual(loaded["session_cookies"]["sid"], "abc")


class ConcurrentBlackboardDispatchTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def test_multi_target_task_attaches_shared_blackboard_without_site_collab(self):
        async with self.Session() as s:
            task = Task(id="t_bb", name="并发协同任务", target_source="fofa", concurrency=2, status="running")
            t1 = Target(id="tg1", task_id="t_bb", url="https://a.edu.cn", host="a.edu.cn", source="fofa", status="queued")
            t2 = Target(id="tg2", task_id="t_bb", url="https://b.edu.cn", host="b.edu.cn", source="fofa", status="queued")
            s.add_all([task, t1, t2])
            await s.commit()

        runner = TaskRunner("t_bb")
        seen_blackboards = []

        class _FakeWorker:
            def __init__(self, *args, **kwargs):
                seen_blackboards.append(kwargs.get("blackboard"))
                self.executor = SimpleNamespace(kill_processes=lambda: None)

            def run(self):
                return SimpleNamespace(model_dump=lambda mode="json": {
                    "verdict": "no_vuln",
                    "findings": [],
                    "summary": "ok",
                })

        fake_llm = SimpleNamespace(_endpoints=[])
        import app.orchestrator.workers as workers_mod
        with (
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
            patch.object(workers_mod, "AGENT_EXECUTOR", pool),
            patch.object(workers_mod, "SessionLocal", self.Session),
            patch.object(workers_mod, "Worker", _FakeWorker),
            patch.object(workers_mod, "_llm_for_task", return_value=fake_llm),
            patch.object(runner, "_persist_worker_result", AsyncMock()),
            patch.object(runner, "_build_duplicate_history", AsyncMock(return_value=[])),
            patch.object(runner, "_flush_trace_buffer", AsyncMock()),
        ):
            runner._live["tg1"] = {"host": "a.edu.cn"}
            runner._live["tg2"] = {"host": "b.edu.cn"}
            await runner._run_worker_inner("t_bb", "tg1", "https://a.edu.cn", threading.Event())
            await runner._run_worker_inner("t_bb", "tg2", "https://b.edu.cn", threading.Event())

        self.assertEqual(len(seen_blackboards), 2)
        self.assertIsNotNone(seen_blackboards[0])
        self.assertIs(seen_blackboards[0], seen_blackboards[1])
        seen_blackboards[0].publish("cred", "admin:123", worker_id="tg1")
        q_res = seen_blackboards[1].query("cred")
        self.assertTrue(any(it.get("value") == "admin:123" for it in q_res.get("entries", [])))


class HardTargetReviveApiTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(tasks_api.router)
        self.app.dependency_overrides[tasks_api.get_session] = _override_session

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def test_revive_single_and_batch_hard_targets_with_intel_injection(self):
        async with self.Session() as s:
            task = Task(id="t_rev", name="唤醒测试任务", status="stopped")
            tg_dead = Target(
                id="tg_dead",
                task_id="t_rev",
                url="https://dead.edu.cn",
                host="dead.edu.cn",
                status="dead",
                dead_reason="连续超时",
                last_error="ReadTimeout",
                retry_count=3,
                assigned_worker="w1",
            )
            tg_skip = Target(
                id="tg_skip",
                task_id="t_rev",
                url="https://skip.edu.cn",
                host="skip.edu.cn",
                status="skipped",
                dead_reason="WAF阻断",
                retry_count=2,
            )
            kb = Intel(
                kind="knowledge",
                match_key="distilled-shiro",
                dedup_hash="k1",
                payload={"origin": "distilled", "content": "# Shiro bypass"},
                summary="Shiro 实战绕过指南",
                confidence="verified",
            )
            s.add_all([task, tg_dead, tg_skip, kb])
            await s.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            res = await client.post("/api/tasks/hard-targets/revive", json={
                "target_ids": ["tg_dead"],
                "inject_latest_intel": True,
            })
            self.assertEqual(res.status_code, 200, res.text)
            body = res.json()
            self.assertTrue(body["ok"])
            self.assertEqual(body["revived_count"], 1)
            self.assertEqual(body["target_ids"], ["tg_dead"])

            async with self.Session() as s:
                t1 = await s.get(Target, "tg_dead")
                t2 = await s.get(Target, "tg_skip")
                tk = await s.get(Task, "t_rev")
                self.assertEqual(t1.status, "queued")
                self.assertEqual(t1.dead_reason, "")
                self.assertEqual(t1.last_error, "")
                self.assertEqual(t1.assigned_worker, "")
                self.assertEqual(t1.retry_count, 0)
                self.assertEqual((t1.deepen_context or {}).get("source"), "hard_target_revive")
                self.assertIn("Shiro 实战绕过指南", (t1.deepen_context or {}).get("directive", ""))
                self.assertEqual(tk.status, "created")
                self.assertEqual(t2.status, "skipped")

                # Worker 收到硬骨头唤醒上下文时渲染专属提示且不走误跳过早收尾捷径
                w = Worker("https://dead.edu.cn", llm=SimpleNamespace(), deepen_context=t1.deepen_context)
                brief = w._deepen_brief()
                self.assertIn("硬骨头回捞重测", brief)
                self.assertIn("连续超时", brief)
                self.assertIn("Shiro 实战绕过指南", brief)

            # 按过滤条件批量唤醒剩余 skipped 目标
            res2 = await client.post("/api/tasks/hard-targets/revive", json={
                "status": "skipped",
                "q": "skip.edu.cn",
                "inject_latest_intel": False,
            })
            self.assertEqual(res2.status_code, 200)
            self.assertEqual(res2.json()["revived_count"], 1)
            async with self.Session() as s:
                t2 = await s.get(Target, "tg_skip")
                self.assertEqual(t2.status, "queued")


if __name__ == "__main__":
    unittest.main()
