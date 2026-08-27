"""设置页新增接口：引擎连接测试 / 配置导入导出 / 全局健康总览。"""
import asyncio
import unittest
from unittest import mock

import app.api.settings as settings_mod
from app.api.settings import (
    EngineTestRequest,
    SettingsImportRequest,
    export_settings_api,
    health_overview,
    import_settings_api,
)


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class EngineTestTests(unittest.TestCase):
    def test_unknown_engine_404(self):
        body = EngineTestRequest(engine="nope")
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock):
            with self.assertRaises(Exception):
                asyncio.run(settings_mod.test_engine(body, _FakeSession()))

    def test_no_key_auth(self):
        body = EngineTestRequest(engine="fofa")
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.resolve_engine_key", return_value=""):
            res = asyncio.run(settings_mod.test_engine(body, _FakeSession()))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_type"], "auth")

    def test_success(self):
        body = EngineTestRequest(engine="fofa", key="test-key")
        engine = mock.Mock()
        engine.test_connection = mock.AsyncMock(
            return_value={"ok": True, "engine": "fofa", "latency_ms": 50, "size": 10}
        )
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.get_engine", return_value=engine):
            res = asyncio.run(settings_mod.test_engine(body, _FakeSession()))
        self.assertTrue(res["ok"])
        self.assertEqual(res["size"], 10)
        self.assertEqual(res["latency_ms"], 50)

    def test_error_classified_auth(self):
        body = EngineTestRequest(engine="fofa", key="test-key")
        engine = mock.Mock()
        engine.test_connection = mock.AsyncMock(side_effect=ValueError("invalid key"))
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.get_engine", return_value=engine):
            res = asyncio.run(settings_mod.test_engine(body, _FakeSession()))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_type"], "auth")

    def test_error_classified_network(self):
        body = EngineTestRequest(engine="fofa", key="test-key")
        engine = mock.Mock()
        engine.test_connection = mock.AsyncMock(side_effect=TimeoutError("connect timeout"))
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.get_engine", return_value=engine):
            res = asyncio.run(settings_mod.test_engine(body, _FakeSession()))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_type"], "network")


class ExportImportTests(unittest.TestCase):
    FAKE_EFF = {
        "llm": {
            "mode": "single",
            "base_url": "https://api.example.com/v1",
            "model": "test-model",
            "protocol": "openai_chat",
            "temperature": 0.3,
            "api_key": "sk-test-secret",
            "providers": [],
        },
        "fofa": {"key": "fofa-key", "base_url": "", "max_pages": 20, "page_size": 100, "default_intent_mode": ""},
        "engines": {"fofa": {"key": "fofa-key", "base_url": ""}},
        "defaults": {"concurrency": 3, "deepen_cap": 2, "skip_score_threshold": -10, "worker_prompt_version": "legacy", "engine": "fofa"},
        "ui": {"theme": "dark", "saved": True},
    }

    def test_export_structure_with_secrets(self):
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.settings_service.effective_settings", return_value=self.FAKE_EFF):
            res = asyncio.run(export_settings_api(_FakeSession()))
        self.assertEqual(res["version"], 1)
        for key in ("llm", "fofa", "engines", "defaults", "ui"):
            self.assertIn(key, res)
        # 导出应含明文密钥（管理员主动备份）
        self.assertEqual(res["llm"]["api_key"], "sk-test-secret")
        self.assertEqual(res["fofa"]["key"], "fofa-key")

    def test_import_empty_400(self):
        body = SettingsImportRequest()
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock):
            with self.assertRaises(Exception):
                asyncio.run(import_settings_api(body, _FakeSession()))

    def test_import_calls_update(self):
        body = SettingsImportRequest(defaults={"concurrency": 5})
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.update_settings", new_callable=mock.AsyncMock, return_value={}) as upd:
            res = asyncio.run(import_settings_api(body, _FakeSession()))
        upd.assert_awaited_once()
        self.assertEqual(upd.await_args.args[1]["defaults"]["concurrency"], 5)


class HealthOverviewTests(unittest.TestCase):
    FAKE_VIEW = {
        "updated_at": "2026-08-23T00:00:00",
        "llm": {
            "mode": "pool",
            "providers": [
                {"name": "a", "enabled": True, "health": {"status": "ok"}},
                {"name": "b", "enabled": True, "health": {"status": "cooldown"}},
            ],
        },
        "engines": {"fofa": {"key_set": True}, "quake": {"key_set": False}},
        "available_engines": [
            {"name": "fofa", "display_name": "FOFA"},
            {"name": "quake", "display_name": "Quake"},
        ],
        "defaults": {"engine": "fofa"},
    }

    def test_structure(self):
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.public_settings_view", return_value=self.FAKE_VIEW), \
             mock.patch("app.api.settings.get_workdir_stats", return_value={
                 "total_size_human": "1.2 MB", "total_dirs": 3, "auto_cleanup_enabled": True,
             }):
            res = asyncio.run(health_overview(_FakeSession()))
        self.assertIn("llm", res)
        self.assertIn("engines", res)
        self.assertIn("disk", res)
        # 有 cooldown 端点 → degraded
        self.assertTrue(res["llm"]["degraded"])
        self.assertFalse(res["llm"]["healthy"])
        self.assertEqual(res["engines"]["configured"], 1)
        self.assertEqual(res["disk"]["work_size_human"], "1.2 MB")

    def test_healthy_when_all_ok(self):
        view = dict(self.FAKE_VIEW)
        view["llm"] = {
            "mode": "single",
            "providers": [{"name": "a", "enabled": True, "health": {"status": "ok"}}],
        }
        with mock.patch("app.api.settings.refresh_cache", new_callable=mock.AsyncMock), \
             mock.patch("app.api.settings.public_settings_view", return_value=view), \
             mock.patch("app.api.settings.get_workdir_stats", return_value={}):
            res = asyncio.run(health_overview(_FakeSession()))
        self.assertTrue(res["llm"]["healthy"])
        self.assertFalse(res["llm"]["degraded"])
