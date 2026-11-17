"""本轮工程推进回归：主界面目标达成与 L1-L4 影响内联、情报定时同步、版本与线程信号安全。"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import main as main_mod
from app import security, settings_service
from app.api import findings, fusion, tasks
from app.db.models import Base, Finding, FusionGoal, Intel, Review, Target, Task
from app.fusion import config, evidence_gate, vulnintel
from app.report_export import (
    build_docx_bytes,
    build_report_html,
    build_report_markdown,
    build_report_sections,
)


class FusionConfigAndSchedulerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="_fusion_sync_")
        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{Path(self.tmp.name) / 'sync.db'}", future=True
        )
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        self._cache_snapshot = dict(settings_service._cache)

    async def asyncTearDown(self):
        settings_service._cache = self._cache_snapshot
        await self.engine.dispose()
        self.tmp.cleanup()

    def test_intel_sync_interval_config_and_clamping(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FUSION_INTEL_SYNC_INTERVAL_HOURS", None)
            self.assertEqual(config.load_config(overlay={}).intel_sync_interval_hours, 0)
            os.environ["FUSION_INTEL_SYNC_INTERVAL_HOURS"] = "12"
            self.assertEqual(config.load_config(overlay={}).intel_sync_interval_hours, 12)
        patch_hi = config.writable_patch({"intel_sync_interval_hours": 9999})
        self.assertEqual(patch_hi["intel_sync_interval_hours"], 720)
        patch_lo = config.writable_patch({"intel_sync_interval_hours": -5})
        self.assertEqual(patch_lo["intel_sync_interval_hours"], 0)
        pub = config.public_config(overlay={"intel_sync_interval_hours": 6})
        self.assertEqual(pub["intel_sync_interval_hours"], 6)

    async def test_sync_and_store_idempotent_with_injected_fetcher(self):
        calls = []

        def fake_fetcher(url, params, headers):
            calls.append(url)
            if "cves/2.0" in url:
                return {
                    "vulnerabilities": [{
                        "cve": {
                            "id": "CVE-2026-0001",
                            "descriptions": [{"lang": "en", "value": "Test RCE in demo app"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:demo_app:*:*:*:*:*:*:*:*"}]}]}],
                        }
                    }]
                }
            return {"vulnerabilities": [{"cveID": "CVE-2026-0001", "vulnerabilityName": "Demo App RCE", "vendorProject": "vendor", "product": "demo_app"}]}

        cfg = config.load_config(overlay={"intel_sync_enabled": True})
        async with self.Session() as s:
            r1 = await vulnintel.sync_and_store(s, fetcher=fake_fetcher, cfg=cfg)
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["stored"], 1)
            r2 = await vulnintel.sync_and_store(s, fetcher=fake_fetcher, cfg=cfg)
            self.assertEqual(r2["stored"], 1)
            rows = (await s.execute(select(Intel).where(Intel.kind == vulnintel.INTEL_KIND))).scalars().all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].hit_count, 2)
        self.assertEqual(len(calls), 4)

    async def test_periodic_intel_sync_runs_when_enabled_and_stops_when_cancelled(self):
        loop = asyncio.get_running_loop()
        called = asyncio.Event()

        def fake_fetcher(url, params, headers):
            loop.call_soon_threadsafe(called.set)
            return {"vulnerabilities": []}

        settings_service._cache = {"defaults": {"fusion": {"intel_sync_enabled": True, "intel_sync_interval_hours": 1}}}
        task = asyncio.create_task(
            vulnintel.run_periodic_intel_sync(
                session_factory=self.Session,
                fetcher=fake_fetcher,
                poll_seconds=0.05,
            )
        )
        await asyncio.wait_for(called.wait(), timeout=5.0)
        task.cancel()
        await asyncio.wait_for(task, timeout=5.0)

    async def test_periodic_intel_sync_idle_when_interval_zero(self):
        calls = []

        def fake_fetcher(url, params, headers):
            calls.append(url)
            return {"vulnerabilities": []}

        settings_service._cache = {"defaults": {"fusion": {"intel_sync_enabled": True, "intel_sync_interval_hours": 0}}}
        task = asyncio.create_task(
            vulnintel.run_periodic_intel_sync(
                session_factory=self.Session,
                fetcher=fake_fetcher,
                poll_seconds=0.02,
            )
        )
        await asyncio.sleep(0.08)
        task.cancel()
        await asyncio.wait_for(task, timeout=5.0)
        self.assertEqual(calls, [])


class InlineGoalAndImpactTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="_fusion_inline_")
        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{Path(self.tmp.name) / 'inline.db'}", future=True
        )
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(tasks.router)
        self.app.include_router(findings.router)
        self.app.include_router(fusion.router)
        self.app.dependency_overrides[tasks.get_session] = _override_session
        self.app.dependency_overrides[findings.get_session] = _override_session
        self.app.dependency_overrides[fusion.get_session] = _override_session
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        )
        self._cache_snapshot = dict(settings_service._cache)
        self._token_snapshot = dict(security._db_tokens)
        settings_service._cache = {"defaults": {"fusion": {"goal_gate_enabled": True}}}
        await self._seed()

    async def asyncTearDown(self):
        settings_service._cache = self._cache_snapshot
        security._db_tokens.clear()
        security._db_tokens.update(self._token_snapshot)
        await self.client.aclose()
        await self.engine.dispose()
        self.tmp.cleanup()

    async def _seed(self):
        async with self.Session() as s:
            s.add(Task(id="T-GOAL", name="内联测试任务", status="running", manual_targets=["https://demo.edu.cn"]))
            s.add(Task(id="T-PLAIN", name="普通任务", status="created", manual_targets=["https://plain.edu.cn"]))
            s.add(Target(id="TG-1", task_id="T-GOAL", url="https://demo.edu.cn/api", host="demo.edu.cn", status="done"))
            s.add(Finding(
                id="F-RCE", task_id="T-GOAL", target_id="TG-1", worker_id="w1",
                vuln_type="rce", title="命令执行漏洞", severity_claimed="critical",
                target_url="https://demo.edu.cn/api", owner="测试单位",
                description="可直接执行系统命令。", affected_scope="全部后端节点",
                poc="curl -s 'https://demo.edu.cn/api?cmd=id'",
                raw_request="GET /api?cmd=id HTTP/1.1\nHost: demo.edu.cn\n\n",
                raw_response="HTTP/1.1 200 OK\n\nuid=0(root)",
                evidence={"status_code": 200},
            ))
            s.add(Review(
                id="R-RCE", finding_id="F-RCE", task_id="T-GOAL",
                verdict="accepted", confidence="confirmed", severity_final="严重",
                score=9.2, in_scope=True, reproduced=True, reviewer_notes="已复现",
                user_status="pending",
            ))
            s.add(Finding(
                id="F-WEAK", task_id="T-GOAL", target_id="TG-1", worker_id="w2",
                vuln_type="info_leak", title="版本号暴露", severity_claimed="critical",
                target_url="https://demo.edu.cn/ver", owner="测试单位",
                description="疑似存在版本泄露", affected_scope="首页",
                poc="", raw_request="", raw_response="", evidence={},
            ))
            s.add(FusionGoal(
                task_id="T-GOAL", goal_key="g1", title="获取命令执行能力",
                criteria="返回 HTTP 200 且输出 uid=", kind="capability",
                match_terms=["命令执行", "rce"], status="open",
            ))
            s.add(FusionGoal(
                task_id="T-GOAL", goal_key="g2", title="越权读取业务数据",
                criteria="返回 200 且包含业务字段", kind="capability",
                match_terms=["越权读取"], status="open",
            ))
            await s.commit()

    async def test_tasks_list_detail_and_board_expose_goal_summary(self):
        listed = (await self.client.get("/api/tasks")).json()
        by_id = {t["id"]: t for t in listed}
        self.assertEqual(by_id["T-GOAL"]["goal_summary"]["summary"], "1/2 目标达成")
        self.assertEqual(by_id["T-GOAL"]["goal_summary"]["terminal_state"], "incomplete")
        self.assertIsNone(by_id["T-PLAIN"]["goal_summary"])

        detail = (await self.client.get("/api/tasks/T-GOAL")).json()
        self.assertEqual(detail["goal_summary"]["met_count"], 1)
        self.assertEqual(detail["goal_summary"]["unmet_ids"], ["g2"])

        board = (await self.client.get("/api/tasks/T-GOAL/board")).json()
        self.assertEqual(board["goal_summary"]["summary"], "1/2 目标达成")

    async def test_observer_cannot_see_goal_summary(self):
        with patch.object(tasks, "_is_observer", return_value=True):
            listed = (await self.client.get("/api/tasks")).json()
            by_id = {t["id"]: t for t in listed}
            self.assertIsNone(by_id["T-GOAL"]["goal_summary"])
            detail = (await self.client.get("/api/tasks/T-GOAL")).json()
            self.assertIsNone(detail["goal_summary"])
            board = (await self.client.get("/api/tasks/T-GOAL/board")).json()
            self.assertIsNone(board["goal_summary"])

    async def test_findings_and_report_include_impact_and_goals(self):
        rows = (await self.client.get("/api/tasks/T-GOAL/findings", params={"compact": True})).json()
        by_id = {f["id"]: f for f in rows}
        self.assertEqual(by_id["F-RCE"]["fusion_evidence"]["impact_level"], "L3")
        self.assertTrue(by_id["F-RCE"]["fusion_evidence"]["allowed"])
        self.assertEqual(by_id["F-WEAK"]["fusion_evidence"]["impact_level"], "L1")
        self.assertFalse(by_id["F-WEAK"]["fusion_evidence"]["allowed"])

        detail = (await self.client.get("/api/findings/F-RCE")).json()
        self.assertEqual(detail["fusion_evidence"]["impact_level"], "L3")
        self.assertEqual(detail["fusion_goals"]["summary"], "1/2 目标达成")

    def test_evidence_gate_respects_review_severity_and_edits(self):
        f = SimpleNamespace(
            title="版本信息暴露", description="响应头包含版本号", vuln_type="info",
            severity_claimed="critical", affected_scope="全局", poc="", poc_http="",
            raw_request="", raw_response="", owner="", steps=[], evidence={},
        )
        self.assertFalse(evidence_gate.check_finding_with_review(f, None)["allowed"])
        r_down = SimpleNamespace(user_severity="低危", severity_final="高危", user_edits={})
        self.assertTrue(evidence_gate.check_finding_with_review(f, r_down)["allowed"])

    def test_report_export_embeds_impact_level(self):
        f = SimpleNamespace(
            id="F1", task_id="T1", target_id="TG1", vuln_type="rce", title="RCE 测试",
            severity_claimed="严重", target_url="https://demo.edu.cn", owner="测试单位",
            description="desc", affected_scope="scope", steps=[], poc="curl -s https://demo.edu.cn",
            poc_http="", raw_request="GET / HTTP/1.1\nHost: demo.edu.cn\n\n",
            raw_response="HTTP/1.1 200 OK\n\nuid=0(root)", evidence={}, kill_chain=[],
            created_at=None, edu_school="测试单位",
        )
        sec = build_report_sections(f, None, "edusrc")
        self.assertEqual(sec["data"]["overview"]["impact_level"], "L3")
        self.assertIn("影响分级", build_report_markdown(f, None, "edusrc"))
        self.assertIn("影响分级", build_report_html(f, None, "edusrc"))
        import io
        import zipfile
        zf = zipfile.ZipFile(io.BytesIO(build_docx_bytes(f, None, "edusrc")))
        self.assertIn("影响分级：L3", zf.read("word/document.xml").decode("utf-8"))


class SettingsFusionAndCveIntelApiTest(unittest.IsolatedAsyncioTestCase):
    """Settings defaults.fusion 读写同步与 Intel API cve_feed 收纳回归。"""

    _FUSION_ENV_KEYS = (
        "FUSION_EVIDENCE_GATE_HARD",
        "FUSION_SCOPE_GUARD_HARD",
        "FUSION_TRAFFIC",
        "FUSION_INTEL_SYNC_INTERVAL_HOURS",
        "FUSION_INTEL_SYNC",
        "NVD_API_KEY",
    )

    async def asyncSetUp(self):
        from app.api import intel as intel_api
        from app.api import settings as settings_api

        self._env_backup = {k: os.environ.get(k) for k in self._FUSION_ENV_KEYS}
        for k in self._FUSION_ENV_KEYS:
            os.environ.pop(k, None)

        self._cache_snapshot = dict(settings_service._cache)
        settings_service._cache = {}

        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(settings_api.router)
        self.app.include_router(intel_api.router)
        self.app.include_router(fusion.router)
        self.app.dependency_overrides[settings_api.get_session] = _override_session
        self.app.dependency_overrides[intel_api.get_session] = _override_session
        self.app.dependency_overrides[fusion.get_session] = _override_session

    async def asyncTearDown(self):
        settings_service._cache = self._cache_snapshot
        for k, val in self._env_backup.items():
            if val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = val
        await self.engine.dispose()

    async def test_settings_defaults_fusion_roundtrip_and_nvd_key_dropped(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            r1 = await client.get("/api/settings")
            self.assertEqual(r1.status_code, 200, r1.text)
            defaults1 = r1.json()["defaults"]
            self.assertIn("fusion", defaults1)
            self.assertIs(defaults1["fusion"]["evidence_gate_hard"], False)
            self.assertEqual(defaults1["fusion"]["intel_sync_interval_hours"], 0)

            r2 = await client.put("/api/settings", json={
                "defaults": {
                    "fusion": {
                        "evidence_gate_hard": True,
                        "intel_sync_interval_hours": 12,
                        "nvd_api_key": "drop-me-never-store",
                    }
                }
            })
            self.assertEqual(r2.status_code, 200, r2.text)
            fusion_after = r2.json()["defaults"]["fusion"]
            self.assertIs(fusion_after["evidence_gate_hard"], True)
            self.assertEqual(fusion_after["intel_sync_interval_hours"], 12)
            self.assertNotIn("nvd_api_key", fusion_after)

            cfg = config.load_config()
            self.assertIs(cfg.evidence_gate_hard, True)
            self.assertEqual(cfg.intel_sync_interval_hours, 12)
            self.assertEqual(cfg.nvd_api_key, "")

            r3 = await client.get("/api/fusion/config")
            self.assertEqual(r3.status_code, 200, r3.text)
            self.assertIs(r3.json()["config"]["evidence_gate_hard"], True)
            self.assertEqual(r3.json()["config"]["intel_sync_interval_hours"], 12)
            self.assertNotIn("nvd_api_key", r3.json()["config"])

    async def test_intel_stats_and_list_include_cve_feed(self):
        def fake_fetcher(url, params, headers):
            if "nvd.nist.gov" in url:
                return {"vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2026-9901",
                        "descriptions": [{"lang": "en", "value": "Spring remote execution"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    }
                }]}
            return {"vulnerabilities": [{
                "cveID": "CVE-2026-9901",
                "vulnerabilityName": "Spring RCE",
                "vendorProject": "spring",
                "product": "boot",
                "dateAdded": "2026-04-01",
            }]}

        cfg = config.load_config(overlay={"intel_sync_enabled": True})
        async with self.Session() as session:
            res = await vulnintel.sync_and_store(session, fetcher=fake_fetcher, cfg=cfg)
            self.assertGreaterEqual(res["stored"], 1)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            stats_res = await client.get("/api/intel/stats")
            self.assertEqual(stats_res.status_code, 200, stats_res.text)
            stats_body = stats_res.json()
            self.assertIn("cve_feed", stats_body["by_kind"])
            self.assertGreaterEqual(stats_body["by_kind"]["cve_feed"], 1)
            self.assertGreaterEqual(stats_body["total"], 1)

            list_res = await client.get("/api/intel", params={"kind": "cve_feed"})
            self.assertEqual(list_res.status_code, 200, list_res.text)
            rows = list_res.json()
            self.assertGreaterEqual(len(rows), 1)
            self.assertEqual(rows[0]["kind"], "cve_feed")
            self.assertEqual(rows[0]["payload"]["cve_id"], "CVE-2026-9901")
            self.assertIs(rows[0]["payload"]["kev"], True)


class DiagnosticsAndVersionTest(unittest.TestCase):
    def test_version_matches_file(self):
        expected = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(main_mod.APP_VERSION, expected)

    def test_install_diagnostics_safe_in_non_main_thread_even_with_sigusr1(self):
        errors = []
        called_signal = []

        def fake_signal(sig, handler):
            called_signal.append(sig)
            raise ValueError("signal only works in main thread")

        def worker():
            loop = asyncio.new_event_loop()
            try:
                with patch.object(signal, "SIGUSR1", 10, create=True), \
                     patch.object(signal, "signal", side_effect=fake_signal), \
                     patch.object(main_mod.faulthandler, "register", create=True):
                    main_mod._install_diagnostics(loop)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                loop.close()

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(called_signal, [], "非主线程不应调用 signal.signal")


if __name__ == "__main__":
    unittest.main()
