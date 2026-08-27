"""审核协程异常必须落入退避：脏数据 finding 不能被每个派发周期(3s)重捞重试。"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from app.orchestrator import REVIEW_RETRY_BACKOFF, TaskRunner


class _FakeSessionCtx:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *exc):
        return False


class ReviewBackoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_early_exception_sets_backoff(self):
        runner = TaskRunner("t1")
        runner._review_inflight.add("f1")
        t0 = asyncio.get_running_loop().time()
        with mock.patch.object(runner, "_run_review_inner", side_effect=ValueError("boom")), \
             mock.patch("app.orchestrator.SessionLocal", _FakeSessionCtx), \
             mock.patch.object(runner, "_log", new=mock.AsyncMock()):
            await runner._run_review("t1", "f1")

        exp = runner._review_backoff.get("f1")
        self.assertIsNotNone(exp, "前置异常必须设置退避，否则每个派发周期重试刷屏")
        self.assertGreaterEqual(exp, t0 + REVIEW_RETRY_BACKOFF - 1)
        self.assertNotIn("f1", runner._review_inflight)
        self.assertNotIn("f1", runner._review_tasks)

    async def test_success_path_no_backoff(self):
        runner = TaskRunner("t1")
        with mock.patch.object(runner, "_run_review_inner", new=mock.AsyncMock()):
            await runner._run_review("t1", "f2")
        self.assertNotIn("f2", runner._review_backoff)


if __name__ == "__main__":
    unittest.main()
