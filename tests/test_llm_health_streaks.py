"""冷却档位阶梯回归：flapping 端点单次成功不再清零档位；连续健康才整体复位。

另含 429 Retry-After 响应头解析。
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.llm import health as health_mod  # noqa: E402
from app.llm.health import provider_ref  # noqa: E402


def _ref(url, model="m"):
    return provider_ref(url, model, "", "auto")
from app.llm.client import _parse_retry_after  # noqa: E402


def _fail(url="u", model="m"):
    return health_mod.mark_provider_failed(url, model, "mock failure", kind="network")


def _ok(url="u", model="m"):
    return health_mod.mark_provider_ok(url, model)


class CooldownStreakTest(unittest.TestCase):
    def setUp(self):
        health_mod._HEALTH.clear()
        self.addCleanup(health_mod._HEALTH.clear)

    def _drive_to_cooldown(self):
        """连续失败到阈值，触发第一次冷却。"""
        with (
            __import__("unittest").mock.patch.object(health_mod, "_FAIL_THRESHOLD", 2),
            __import__("unittest").mock.patch.object(health_mod, "_COOLDOWN_STEPS", [60, 900]),
        ):
            for _ in range(2):
                _fail()

    def test_flapping_endpoint_escalates(self):
        """冷却到期→成功 1 次→再失败：第二次熔断必须进更高档（不再永停最低档）。"""
        self._drive_to_cooldown()
        row = health_mod._HEALTH[_ref("u")]
        self.assertEqual(row["cooldown_count"], 1)
        self.assertEqual(row["cooldown_seconds"], 60)

        _ok()  # 半开探测成功
        self.assertEqual(health_mod._HEALTH[_ref("u")]["cooldown_count"], 1)  # 不清零

        with (
            __import__("unittest").mock.patch.object(health_mod, "_FAIL_THRESHOLD", 2),
            __import__("unittest").mock.patch.object(health_mod, "_COOLDOWN_STEPS", [60, 900]),
        ):
            for _ in range(2):
                _fail()
        row = health_mod._HEALTH[_ref("u")]
        self.assertEqual(row["cooldown_count"], 2)
        self.assertEqual(row["cooldown_seconds"], 900)

    def test_ok_streak_resets_cooldown_count(self):
        """连续健康达到 _OK_STREAK_RESET 后整体复位。"""
        self._drive_to_cooldown()
        self.assertEqual(health_mod._HEALTH[_ref("u")]["cooldown_count"], 1)
        for _ in range(health_mod._OK_STREAK_RESET):
            _ok()
        self.assertEqual(health_mod._HEALTH[_ref("u")]["cooldown_count"], 0)
        self.assertEqual(health_mod._HEALTH[_ref("u")]["consecutive_ok"], 0)

    def test_failure_resets_ok_streak(self):
        _ok()
        _fail()
        self.assertEqual(int(health_mod._HEALTH[_ref("u")]["consecutive_ok"] or 0), 0)


class BehaviorStreakTest(unittest.TestCase):
    def setUp(self):
        health_mod._HEALTH.clear()
        self.addCleanup(health_mod._HEALTH.clear)

    def test_behavior_ok_keeps_cooldown_count(self):
        health_mod.mark_provider_behavior_failed("u2", "m", "bad behavior")
        row = health_mod.mark_provider_behavior_ok("u2", "m")
        self.assertEqual(int(row.get("behavior_cooldown_count") or 0), 0)  # 从未熔断过，保持 0

        # 驱动一次完整 behavior 熔断
        with (
            __import__("unittest").mock.patch.object(health_mod, "_BEHAVIOR_FAIL_THRESHOLD", 1),
            __import__("unittest").mock.patch.object(health_mod, "_COOLDOWN_STEPS", [60, 900]),
        ):
            health_mod.mark_provider_behavior_failed("u2", "m", "bad behavior")
            self.assertEqual(health_mod._HEALTH[_ref("u2")].get("behavior_cooldown_count"), 1)
            health_mod.mark_provider_behavior_ok("u2", "m")
            self.assertEqual(health_mod._HEALTH[_ref("u2")].get("behavior_cooldown_count"), 1)


class RetryAfterTest(unittest.TestCase):
    def _resp(self, header=None):
        headers = {"retry-after": header} if header is not None else {}
        return Mock(headers=headers)

    def test_numeric(self):
        self.assertEqual(_parse_retry_after(self._resp("17")), 17)

    def test_capped_at_300(self):
        self.assertEqual(_parse_retry_after(self._resp("9999")), 300)

    def test_http_date(self):
        import email.utils
        import time as _time
        future = _time.time() + 120
        val = email.utils.formatdate(future, usegmt=True)
        got = _parse_retry_after(self._resp(val))
        self.assertTrue(90 <= got <= 120)

    def test_missing_or_garbage(self):
        self.assertEqual(_parse_retry_after(self._resp(None)), 0)
        self.assertEqual(_parse_retry_after(self._resp("soon-ish")), 0)
        self.assertEqual(_parse_retry_after(None), 0)


if __name__ == "__main__":
    unittest.main()
