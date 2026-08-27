"""设置页自定义访问令牌：DB 持久化 / env 兜底 / 脱敏 / 更新语义。"""
import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import settings_service
from app import security
from app.api.dto import SettingsUpdateRequest

MASK = "••••••••"


class _FakeRow:
    """模拟 SystemSettings 行对象（含 auth 列）。"""

    def __init__(self, auth=None):
        self.id = "global"
        self.llm = {}
        self.fofa = {}
        self.engines = {}
        self.defaults = {}
        self.ui = {}
        self.auth = dict(auth or {})
        self.updated_at = None


class _FakeSession:
    def __init__(self, row):
        self._row = row

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def get(self, _model, _pk):
        return self._row

    async def commit(self):
        pass

    async def refresh(self, row):
        return row


class DbTokenPriorityTests(unittest.TestCase):
    """security.py：DB 令牌优先于环境变量。"""

    def tearDown(self):
        security.set_db_tokens("", "", "")

    def test_db_token_wins_over_env(self):
        with mock.patch.dict(os.environ, {"RIDDLE_API_TOKEN": "env-full"}, clear=False):
            security.set_db_tokens(full="db-full")
            self.assertEqual(security.configured_full_token(), "db-full")

    def test_env_fallback_when_db_empty(self):
        with mock.patch.dict(os.environ, {"RIDDLE_API_TOKEN": "env-full"}, clear=False):
            security.set_db_tokens("", "", "")
            self.assertEqual(security.configured_full_token(), "env-full")

    def test_all_three_roles(self):
        security.set_db_tokens(full="f", read="r", observer="o")
        self.assertEqual(security.configured_full_token(), "f")
        self.assertEqual(security.configured_read_token(), "r")
        self.assertEqual(security.configured_observer_token(), "o")

    def test_auth_enabled(self):
        security.set_db_tokens("", "", "")
        self.assertFalse(security.auth_enabled())
        security.set_db_tokens(read="r")
        self.assertTrue(security.auth_enabled())


class UpdateAuthTests(unittest.TestCase):
    """settings_service.update_settings 的 auth 更新语义。"""

    def _run(self, row, payload):
        with mock.patch.object(settings_service, "refresh_cache", new=mock.AsyncMock()):
            return asyncio.run(settings_service.update_settings(_FakeSession(row), payload))

    def test_set_tokens(self):
        row = _FakeRow()
        self._run(row, {"auth": {"full_token": "tok-full", "read_token": "tok-read"}})
        self.assertEqual(row.auth["full_token"], "tok-full")
        self.assertEqual(row.auth["read_token"], "tok-read")
        self.assertNotIn("observer_token", row.auth)

    def test_masked_placeholder_keeps_existing(self):
        row = _FakeRow({"full_token": "secret-1"})
        self._run(row, {"auth": {"full_token": MASK}})
        self.assertEqual(row.auth["full_token"], "secret-1")

    def test_empty_string_clears_token(self):
        row = _FakeRow({"full_token": "secret-1", "read_token": "secret-2"})
        self._run(row, {"auth": {"full_token": ""}})
        self.assertNotIn("full_token", row.auth)
        self.assertEqual(row.auth["read_token"], "secret-2")

    def test_unknown_keys_ignored(self):
        row = _FakeRow()
        self._run(row, {"auth": {"hacker_token": "x", "full_token": "ok"}})
        self.assertEqual(row.auth, {"full_token": "ok"})

    def test_auth_none_is_noop(self):
        row = _FakeRow({"full_token": "keep"})
        self._run(row, {"auth": None})
        self.assertEqual(row.auth["full_token"], "keep")


class PublicAuthViewTests(unittest.TestCase):
    """public_settings_view 的 auth 段：脱敏 + 来源标记。"""

    def _view(self, auth, env=None):
        cache = {
            "llm": {}, "fofa": {}, "engines": {}, "defaults": {}, "ui": {},
            "auth": dict(auth or {}), "updated_at": None,
        }
        with mock.patch.object(settings_service, "_cache", cache), \
             mock.patch.object(settings_service, "list_engines", return_value=[]), \
             mock.patch.object(settings_service, "llm_health_snapshot", return_value={}), \
             mock.patch.dict(os.environ, env or {}, clear=False):
            return settings_service.public_settings_view()["auth"]

    def test_masked_and_set_flags(self):
        view = self._view({"full_token": "secret-full"})
        self.assertEqual(view["full_token"], MASK)
        self.assertTrue(view["full_token_set"])
        self.assertFalse(view["read_token_set"])
        self.assertFalse(view["env_full"])

    def test_env_source_flags(self):
        view = self._view({}, env={"RIDDLE_READ_TOKEN": "env-read"})
        self.assertTrue(view["env_read"])
        self.assertFalse(view["env_full"])

    def test_empty_auth(self):
        view = self._view({})
        self.assertFalse(view["full_token_set"])
        self.assertEqual(view["full_token"], "")


class AuthDtoTests(unittest.TestCase):
    """SettingsUpdateRequest 白名单接受 auth 段。"""

    def test_dto_accepts_auth(self):
        body = SettingsUpdateRequest.model_validate({
            "auth": {"full_token": "a", "read_token": "b", "observer_token": "c"},
        })
        auth = body.model_dump(exclude_unset=True)["auth"]
        self.assertEqual(auth["full_token"], "a")
        self.assertEqual(auth["read_token"], "b")
        self.assertEqual(auth["observer_token"], "c")

    def test_dto_drops_unknown_auth_fields(self):
        body = SettingsUpdateRequest.model_validate({
            "auth": {"full_token": "a", "evil": "x"},
        })
        auth = body.model_dump(exclude_unset=True)["auth"]
        self.assertEqual(auth, {"full_token": "a"})


class RefreshCacheSyncTests(unittest.TestCase):
    """refresh_cache 把 DB 令牌同步到 security.py。"""

    def tearDown(self):
        security.set_db_tokens("", "", "")

    def test_syncs_db_tokens(self):
        row = _FakeRow({"full_token": "f", "read_token": "r", "observer_token": "o"})
        with mock.patch.object(settings_service, "set_db_tokens", wraps=security.set_db_tokens):
            asyncio.run(settings_service.refresh_cache(_FakeSession(row)))
        self.assertEqual(security.configured_full_token(), "f")
        self.assertEqual(security.configured_read_token(), "r")
        self.assertEqual(security.configured_observer_token(), "o")


if __name__ == "__main__":
    unittest.main()
