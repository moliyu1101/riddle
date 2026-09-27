"""批次 7 运行时稳定性回归：trace 批量刷盘、取消保留协程引用、WAF 回溯加固、连接池。"""
import asyncio
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.orchestrator import (  # noqa: E402
    TRACE_FLUSH_BATCH,
    TaskRunner,
)
from app.waf import _QUERY_RULES, _multi_unquote  # noqa: E402


def _fake_session_ctx(session):
    ctx = Mock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TraceBufferTest(unittest.IsolatedAsyncioTestCase):
    def _runner(self):
        runner = TaskRunner("t1")
        runner._live["tgt1"] = {"target_id": "tgt1"}
        return runner

    async def test_buffer_then_batch_flush(self):
        runner = self._runner()
        sess = SimpleNamespace(add_all=Mock(), commit=AsyncMock())
        with patch("app.orchestrator.persistence.SessionLocal", return_value=_fake_session_ctx(sess)):
            runner._persist_worker_trace("t1", "tgt1", "tool_http",
                                         {"method": "GET", "url": "https://x.example.edu/a"})
            self.assertEqual(len(runner._trace_buffer), 1, "缓冲阶段不碰 DB")
            sess.add_all.assert_not_called()
            await runner._flush_trace_buffer()
        sess.add_all.assert_called_once()
        self.assertEqual(len(sess.add_all.call_args.args[0]), 1)
        self.assertEqual(runner._trace_buffer, [])

    async def test_batch_threshold_spawns_flush(self):
        runner = self._runner()
        with patch.object(runner, "_spawn_trace_flush") as kick:
            for i in range(TRACE_FLUSH_BATCH):
                runner._persist_worker_trace("t1", "tgt1", "worker_start", {})
            self.assertEqual(kick.call_count, 1, "达到批量阈值时踢一次后台刷盘")

    async def test_fine_kind_skipped_after_live_removed(self):
        runner = self._runner()
        runner._live.clear()
        runner._persist_worker_trace("t1", "tgt1", "tool_http",
                                     {"method": "GET", "url": "https://x/a"})
        self.assertEqual(runner._trace_buffer, [], "worker 收尾后的迟到细粒度事件不落库")


class CancelKeepsRefsTest(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_keeps_worker_refs_until_reap(self):
        runner = TaskRunner("t1")
        blocker = asyncio.create_task(asyncio.sleep(3600))
        runner._active_workers["tid1"] = blocker
        runner._worker_cancel_events["tid1"] = threading.Event()
        empty = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
        sess = SimpleNamespace(execute=AsyncMock(return_value=empty), commit=AsyncMock(),
                               add=Mock())
        try:
            with patch("app.orchestrator.dispatch.SessionLocal", return_value=_fake_session_ctx(sess)), \
                 patch.object(runner, "_log", new=AsyncMock()):
                await runner._cancel_active_workers("测试取消")
            self.assertIn("tid1", runner._active_workers,
                          "取消后保留协程引用：重派被 double_spawn 守卫挡住，不再双打")
            self.assertTrue(runner._worker_cancel_events["tid1"].is_set())
        finally:
            blocker.cancel()
            try:
                await blocker
            except asyncio.CancelledError:
                pass


class WafHardeningTest(unittest.TestCase):
    def _rule(self, name):
        return dict(_QUERY_RULES)[name]

    def test_multi_unquote_peels_deep_encoding(self):
        self.assertIn("<script>", _multi_unquote("%25253Cscript%25253E").lower())
        self.assertEqual(_multi_unquote("plain"), "plain")

    def test_template_probe_still_matches(self):
        pat = self._rule("template_probe")
        self.assertTrue(pat.search("{{config}}"))
        self.assertTrue(pat.search("${T(java.lang.Runtime)}"))

    def test_template_probe_no_catastrophic_backtrack(self):
        pat = self._rule("template_probe")
        blob = "{{" + "a" * 8000  # 无闭合，旧正则最坏指数回溯
        t0 = time.perf_counter()
        pat.search(blob)
        self.assertLess(time.perf_counter() - t0, 0.5)

    def test_sqli_boolean_still_matches(self):
        pat = self._rule("sqli_boolean")
        self.assertTrue(pat.search("1 or 1=1"))
        self.assertTrue(pat.search("x' or 'a'='a"))
        blob = "or " + "a" * 8000 + "=" + "b" * 8000
        t0 = time.perf_counter()
        pat.search(blob)
        self.assertLess(time.perf_counter() - t0, 0.5)


class PoolSizeTest(unittest.TestCase):
    def test_pool_sized_for_single_writer(self):
        from app.db import session as dbmod
        pool = dbmod.engine.sync_engine.pool
        self.assertLessEqual(pool.size(), 10, "SQLite 单写者，池过大只放大写锁竞争")


if __name__ == "__main__":
    unittest.main()
