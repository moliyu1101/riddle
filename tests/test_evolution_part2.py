"""Part 2 自主能力进化引擎测试：情报效用分 / 注入转化率计数 / 实战漏洞一键与自动蒸馏知识库。"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import intel as intel_lib
from app.agents import knowledge
from app.api import findings as findings_api
from app.api import intel as intel_api
from app.db.models import Base, Finding, Intel, Review, Target, Task
from app.orchestrator import manager as orch_manager


class UtilityAndConversionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        knowledge.clear_kb_cache()
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(intel_api.router)
        self.app.dependency_overrides[intel_api.get_session] = _override_session

    async def asyncTearDown(self):
        knowledge.clear_kb_cache()
        await self.engine.dispose()

    async def test_utility_score_orders_high_conversion_and_pitfall_above_rejected(self):
        async with self.Session() as s:
            high_conv = Intel(
                kind="lesson",
                match_key="fp_nacos",
                dedup_hash="h_conv",
                payload={
                    "lesson_type": "poc",
                    "vuln_type": "未授权访问",
                    "repro": "GET /v1/auth/users?pageNo=1",
                    "injected_count": 6,
                    "converted_count": 5,
                    "human_verified": True,
                },
                summary="高效 Nacos 未授权打法",
                confidence="verified",
                hit_count=2,
            )
            noisy_rej = Intel(
                kind="lesson",
                match_key="fp_nacos",
                dedup_hash="h_noisy",
                payload={
                    "lesson_type": "poc",
                    "vuln_type": "信息泄露",
                    "repro": "GET /favicon.ico",
                    "injected_count": 6,
                    "converted_count": 0,
                    "rejected_count": 3,
                },
                summary="低效误报打法",
                confidence="likely",
                hit_count=5,
            )
            pitfall = Intel(
                kind="lesson",
                match_key="fp_nacos",
                dedup_hash="h_pitfall",
                payload={
                    "lesson_type": "pitfall",
                    "vuln_type": "弱口令",
                    "reason": "禁止用仅返回 200 空 JSON 当作已利用",
                    "human_rejected": True,
                },
                summary="人工驳回避坑",
                confidence="verified",
                hit_count=1,
            )
            s.add_all([noisy_rej, high_conv, pitfall])
            await s.commit()

            self.assertGreater(intel_lib.intel_utility_score(high_conv), intel_lib.intel_utility_score(noisy_rej))
            self.assertGreaterEqual(intel_lib.intel_utility_score(pitfall), 4.5)

            hits = await intel_lib.lookup_intel(s, "example.edu.cn", ["fp_nacos"])
            lessons = hits["lesson"]
            self.assertEqual(len(lessons), 3)
            # 高转化与避坑排在多次驳回前面
            summaries = [r.summary for r in lessons]
            self.assertEqual(summaries[-1], "低效误报打法")
            # 注入次数已自增
            self.assertEqual(lessons[summaries.index("高效 Nacos 未授权打法")].payload["injected_count"], 7)

    async def test_conversion_tracking_and_intel_api_exposes_utility_metrics(self):
        async with self.Session() as s:
            cred = Intel(
                kind="cred",
                match_key="univ.edu.cn",
                dedup_hash="c1",
                payload={"username": "admin", "password": "<pw>"},
                summary="test/cred",
                confidence="verified",
            )
            fp = Intel(
                kind="fingerprint",
                match_key="fp_nacos",
                dedup_hash="f1",
                payload={"vuln_type": "未授权访问"},
                summary="Nacos 未授权",
                confidence="verified",
            )
            s.add_all([cred, fp])
            await s.commit()

            hits = await intel_lib.lookup_intel(s, "univ.edu.cn", ["fp_nacos"])
            self.assertEqual(len(hits["cred"]), 1)
            self.assertEqual(len(hits["fingerprint"]), 1)
            await s.commit()

            conv_cnt = await intel_lib.record_intel_conversion(s, "univ.edu.cn", ["fp_nacos"])
            await s.commit()
            self.assertEqual(conv_cnt, 2)

            await s.refresh(cred)
            await s.refresh(fp)
            self.assertEqual(cred.payload["injected_count"], 1)
            self.assertEqual(cred.payload["converted_count"], 1)
            self.assertEqual(fp.payload["converted_count"], 1)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            res = await client.get("/api/intel")
            self.assertEqual(res.status_code, 200)
            items = res.json()
            self.assertEqual(len(items), 2)
            for it in items:
                self.assertIn("utility_score", it)
                self.assertEqual(it["injected_count"], 1)
                self.assertEqual(it["converted_count"], 1)
                self.assertGreater(it["utility_score"], 0)


class AutoDistillKbTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        knowledge.clear_kb_cache()
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(intel_api.router)
        self.app.include_router(findings_api.router)
        self.app.dependency_overrides[intel_api.get_session] = _override_session
        self.app.dependency_overrides[findings_api.get_session] = _override_session

    async def asyncTearDown(self):
        knowledge.clear_kb_cache()
        await self.engine.dispose()

    async def test_manual_distill_api_sanitizes_and_hits_dual_kb_lookup(self):
        async with self.Session() as s:
            task = Task(id="t_dist", name="蒸馏测试")
            tgt = Target(id="tg_dist", task_id="t_dist", url="https://portal.secret-univ.edu.cn/nacos", host="portal.secret-univ.edu.cn")
            f = Finding(
                id="f_dist1",
                task_id="t_dist",
                target_id="tg_dist",
                vuln_type="未授权访问",
                title="portal.secret-univ.edu.cn Nacos 配置接口未授权访问",
                severity_claimed="high",
                target_url="https://portal.secret-univ.edu.cn/nacos/v1/cs/configs",
                description="直连 10.20.30.40 后端未鉴权可读取全部配置。",
                poc="GET /nacos/v1/cs/configs HTTP/1.1\nHost: portal.secret-univ.edu.cn\nCookie: JSESSIONID=supersecret\n",
                raw_response='{"configs":[{"dataId":"app.yml"}]}',
                kill_chain=[
                    {"method": "探测", "detail": "访问 /nacos/v1/cs/configs 跳过登录态"},
                    {"method": "利用", "detail": "读取命名空间配置验证敏感配置泄露"},
                ],
            )
            r = Review(
                id="rev_dist1",
                finding_id="f_dist1",
                task_id="t_dist",
                verdict="accepted",
                confidence="confirmed",
                severity_final="high",
                reviewer_notes="实测可返回配置明细，确认高危",
            )
            s.add_all([task, tgt, f, r])
            await s.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            res = await client.post("/api/intel/knowledge/distill/f_dist1")
            self.assertEqual(res.status_code, 200, res.text)
            body = res.json()
            self.assertTrue(body["ok"])
            item = body["item"]
            self.assertEqual(item["origin"], "distilled")
            self.assertIn("/nacos/v1/cs/configs", item["content"])
            self.assertNotIn("portal.secret-univ.edu.cn", item["content"])
            self.assertNotIn("10.20.30.40", item["content"])
            self.assertNotIn("supersecret", item["content"])
            self.assertIn("<TARGET_HOST>", item["content"])
            self.assertIn("<REDACTED>", item["content"])

            # 同步盘+库检索与异步工作流检索均立即可见
            kb_hit = knowledge.lookup_kb_file("nacos")
            self.assertTrue(kb_hit["ok"])
            self.assertEqual(kb_hit["origin"], "distilled")

            async with self.Session() as s:
                async_hits = await knowledge.lookup_kb(s, query_terms=["未授权访问"])
                self.assertTrue(any(it.match_key == item["match_key"] for it in async_hits))

            # 再次蒸馏幂等递增 hit_count，不重复建行
            res2 = await client.post("/api/intel/knowledge/distill/f_dist1")
            self.assertEqual(res2.status_code, 200)
            self.assertEqual(res2.json()["item"]["hit_count"], 2)

            # 不存在的 finding 返回 404
            res404 = await client.post("/api/intel/knowledge/distill/missing-finding")
            self.assertEqual(res404.status_code, 404)

    async def test_human_pass_high_severity_auto_distills_to_kb_but_low_does_not(self):
        async with self.Session() as s:
            task = Task(id="t_ad", name="自动蒸馏测试")
            tgt = Target(id="tg_ad", task_id="t_ad", url="https://oa.example.edu.cn", host="oa.example.edu.cn")
            f_high = Finding(
                id="f_high",
                task_id="t_ad",
                target_id="tg_ad",
                vuln_type="SQL注入",
                title="Shiro 后台查询接口 SQL 注入",
                severity_claimed="high",
                target_url="https://oa.example.edu.cn/api/query",
                poc="GET /api/query?id=1' AND 1=1-- HTTP/1.1",
            )
            r_high = Review(
                id="rev_high",
                finding_id="f_high",
                task_id="t_ad",
                verdict="accepted",
                confidence="confirmed",
                severity_final="high",
                user_status="pending",
            )
            f_low = Finding(
                id="f_low",
                task_id="t_ad",
                target_id="tg_ad",
                vuln_type="敏感信息泄露",
                title="页面版本号泄露",
                severity_claimed="low",
                target_url="https://oa.example.edu.cn/version",
            )
            r_low = Review(
                id="rev_low",
                finding_id="f_low",
                task_id="t_ad",
                verdict="accepted",
                confidence="likely",
                severity_final="low",
                user_status="pending",
            )
            s.add_all([task, tgt, f_high, r_high, f_low, r_low])
            await s.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with patch.object(orch_manager, "trigger_killsweep", AsyncMock(return_value=False)):
                res_low = await client.patch("/api/results/f_low", json={"user_status": "passed"})
                self.assertEqual(res_low.status_code, 200)
                async with self.Session() as s:
                    rows = (await s.execute(select(Intel).where(Intel.kind == "knowledge"))).scalars().all()
                    self.assertEqual(len(rows), 0)

                res_high = await client.patch("/api/results/f_high", json={"user_status": "passed"})
                self.assertEqual(res_high.status_code, 200)

        async with self.Session() as s:
            kb_rows = (await s.execute(select(Intel).where(Intel.kind == "knowledge"))).scalars().all()
            self.assertEqual(len(kb_rows), 1)
            self.assertEqual((kb_rows[0].payload or {}).get("origin"), "distilled")

        kb_hit = knowledge.lookup_kb_file("shiro")
        self.assertTrue(kb_hit["ok"])
        self.assertEqual(kb_hit["origin"], "distilled")


if __name__ == "__main__":
    unittest.main()
