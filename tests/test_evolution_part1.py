"""Part 1 自主知识闭环测试：KB 双源合并 / 三级锚点沉淀 / 人工复审强反馈 / CVE 提示注入。"""
from __future__ import annotations

import hashlib
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
from app.fusion import role_router, vulnintel
from app.orchestrator import manager as orch_manager


class KnowledgeDualSourceTest(unittest.IsolatedAsyncioTestCase):
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

    async def test_user_kb_created_via_api_visible_to_kb_lookup_and_skill_index(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            res = await client.post("/api/intel/knowledge", json={
                "title": "custom-sign-bypass",
                "category": "user",
                "keyword": "签名绕过 custom-sign-bypass",
                "content": "# 自定义签名绕过手册\n遇到 timestamp+nonce 校验时检查空签名与重放窗口。",
                "enabled": True,
            })
            self.assertEqual(res.status_code, 200, res.text)
            kb_id = res.json()["id"]

            hit = knowledge.lookup_kb_file("custom-sign-bypass")
            self.assertTrue(hit["ok"])
            self.assertEqual(hit["origin"], "user")
            self.assertIn("timestamp+nonce", hit["content"])

            block = role_router.skill_index_block()
            self.assertIn("custom-sign-bypass", block)

            dis = await client.put(f"/api/intel/knowledge/{kb_id}", json={"enabled": False})
            self.assertEqual(dis.status_code, 200)
            miss = knowledge.lookup_kb_file("custom-sign-bypass")
            self.assertFalse(miss["ok"])
            self.assertNotIn("custom-sign-bypass", role_router.skill_index_block())


class ThreeTierIntelAndHumanFeedbackTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(findings_api.router)
        self.app.dependency_overrides[findings_api.get_session] = _override_session

        async with self.Session() as s:
            t = Task(id="TE1", name="定制系统深挖", src_type="edusrc", vuln_types=["越权"])
            tgt = Target(id="TG1", task_id="TE1", host="app.example.edu.cn", url="https://app.example.edu.cn")
            f1 = Finding(
                id="FE1", task_id="TE1", target_id="TG1",
                vuln_type="越权", title="定制门户水平越权读取学籍",
                severity_claimed="high",
                target_url="https://app.example.edu.cn/api/v2/student/detail?id=2",
                owner="某高校",
                poc="curl -s 'https://app.example.edu.cn/api/v2/student/detail?id=2'",
                raw_response='HTTP/1.1 200 OK\n{"studentId":2}',
                evidence={"biz_id": "edu_portal"},
            )
            r1 = Review(
                id="RE1", finding_id="FE1", task_id="TE1",
                verdict="accepted", confidence="confirmed", severity_final="高危",
                reviewer_notes="AI初审确认", user_status="pending",
            )
            f2 = Finding(
                id="FE2", task_id="TE1", target_id="TG1",
                vuln_type="信息泄露", title="普通页面横幅输出",
                severity_claimed="low",
                target_url="https://portal.example.edu.cn/notice/list",
                owner="某高校",
                poc="curl -s https://portal.example.edu.cn/notice/list",
            )
            r2 = Review(
                id="RE2", finding_id="FE2", task_id="TE1",
                verdict="accepted", confidence="likely", severity_final="低危",
                reviewer_notes="AI误判通过", user_status="pending",
            )
            cve_row = Intel(
                id="ICVE1",
                kind=vulnintel.INTEL_KIND,
                match_key="nginx",
                dedup_hash=hashlib.sha1(b"CVE-2026-5050").hexdigest(),
                payload={
                    "cve_id": "CVE-2026-5050", "cvss": 9.1, "kev": True,
                    "products": ["nginx"],
                    "version_ranges": [{"start_including": "1.14.0", "end_excluding": "1.20.0"}],
                },
                summary="CVE-2026-5050 CVSS 9.1｜nginx resolver issue",
                confidence="verified",
            )
            s.add_all([t, tgt, f1, r1, f2, r2, cve_row])
            await s.commit()

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def test_expanded_fingerprints_and_three_tier_fallback(self):
        fps = intel_lib.detect_fingerprints("http://x.com", "蓝凌 EKP 接口", "Set-Cookie: rememberMe=deleteMe")
        self.assertIn("comp_shiro", fps)
        self.assertIn("oa_landray", fps)

        no_fp = {
            "vuln_type": "越权",
            "title": "自研报销单越权查看",
            "target_url": "https://custom.example.com/bill/12",
            "poc": "GET /bill/12 HTTP/1.1",
            "biz_id": "finance",
        }
        self.assertIsNone(intel_lib.distill_review_lesson(no_fp, {"verdict": "accepted"}))
        item = intel_lib.distill_review_lesson(no_fp, {"verdict": "accepted"}, allow_fallback=True)
        self.assertIsNotNone(item)
        self.assertEqual(item["match_key"], "biz_finance")

        async with self.Session() as s:
            await intel_lib.record_intel(
                s, item["kind"], item["match_key"], payload=item["payload"],
                summary=item["summary"], confidence="verified",
            )
            await s.commit()

            hits = await intel_lib.lookup_intel(s, "other.com", [], fallback_keys=["biz_finance"])
            self.assertEqual(len(hits["lesson"]), 1)
            cve_block = await intel_lib.lookup_cve_hints(s, ["nginx/1.18.0"])
            self.assertIn("CVE-2026-5050", cve_block)
            rendered = intel_lib.render_intel_block(hits, cve_block=cve_block)
            self.assertIn("近期关联 CVE 情报提示", rendered)
            self.assertIn("自研报销单越权查看", rendered)

    async def test_human_review_passed_and_rejected_feedback_loop(self):
        with patch.object(orch_manager, "trigger_killsweep", new=AsyncMock(return_value=False)):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.app), base_url="http://test"
            ) as client:
                r_pass = await client.patch("/api/results/FE1", json={
                    "user_status": "passed",
                    "user_edits": {"title": "学籍中心越权查他人档案（精修版）", "poc": "curl -H 'Cookie: u=1' /api/v2/student/detail?id=2"},
                })
                self.assertEqual(r_pass.status_code, 200, r_pass.text)

                # 先模拟一条 AI 误沉淀的 poc，再走人工驳回（含低信号敏感词“仅公开信息”）
                async with self.Session() as s:
                    await intel_lib.record_intel(
                        s, "lesson", "vuln_信息泄露",
                        payload={"lesson_type": "poc", "vuln_type": "信息泄露", "title": "普通页面横幅输出", "repro": "curl /notice/list"},
                        summary="已出洞打法 [信息泄露] 普通页面横幅输出",
                        confidence="verified",
                    )
                    await s.commit()

                r_rej = await client.patch("/api/results/FE2", json={
                    "user_status": "rejected",
                    "user_notes": "仅公开信息通知公告，非敏感漏洞",
                })
                self.assertEqual(r_rej.status_code, 200, r_rej.text)

        async with self.Session() as s:
            rows = (await s.execute(select(Intel).where(Intel.kind.in_(("lesson", "endpoint"))))).scalars().all()
            human_pocs = [r for r in rows if r.kind == "lesson" and (r.payload or {}).get("human_verified")]
            self.assertTrue(any(r.match_key == "biz_edu_portal" and "精修版" in r.summary for r in human_pocs))

            eps = [r for r in rows if r.kind == "endpoint" and (r.payload or {}).get("path") == "/api/v2/student/detail"]
            self.assertEqual(len(eps), 1)

            pitfalls = [r for r in rows if r.kind == "lesson" and (r.payload or {}).get("lesson_type") == "pitfall"]
            self.assertTrue(any((r.payload or {}).get("human_rejected") and "公开信息" in (r.payload or {}).get("reason", "") for r in pitfalls))

            ai_pocs = [r for r in rows if r.kind == "lesson" and r.match_key == "vuln_信息泄露" and (r.payload or {}).get("lesson_type") == "poc"]
            self.assertTrue(any((r.payload or {}).get("rejected_count", 0) >= 1 and r.confidence == "likely" for r in ai_pocs))


if __name__ == "__main__":
    unittest.main()
