"""审核协程异常必须落入退避：脏数据 finding 不能被每个派发周期(3s)重捞重试。"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock
from unittest.mock import AsyncMock

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


import app.orchestrator as orch


class ReviewGiveupTests(unittest.IsolatedAsyncioTestCase):
    """审核超时/异常达上限后自动放行进人工复审队列，不再无限重试烧 LLM。"""

    async def test_giveup_after_max_attempts(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, Mock, patch

        runner = orch.TaskRunner("t1")
        finding = SimpleNamespace(id="f1", status="pending_review", severity_claimed="中危")
        with mock.patch.object(runner, "_run_review_inner", side_effect=ValueError("boom")),              mock.patch("app.orchestrator.SessionLocal", _FakeSessionCtx),              mock.patch("app.orchestrator.asyncio.sleep", new=AsyncMock()),              mock.patch.object(orch, "REVIEW_MAX_ATTEMPTS", 3),              mock.patch("app.orchestrator.SessionLocal") as sl,              mock.patch.object(runner, "_log", new=AsyncMock()):
            # SessionLocal 返回需要支持 get 的会话
            sess = Mock()
            sess.get = AsyncMock(return_value=finding)
            sess.add = Mock()
            sess.commit = AsyncMock()
            ctx = Mock()
            ctx.__aenter__ = AsyncMock(return_value=sess)
            ctx.__aexit__ = AsyncMock(return_value=False)
            sl.return_value = ctx
            for _ in range(3):
                await runner._run_review("t1", "f1")
            self.assertEqual(finding.status, "reviewed")
            sess.add.assert_called()          # 写入放行 Review 记录
            self.assertNotIn("f1", runner._review_attempts)
            self.assertNotIn("f1", runner._review_backoff)

    async def test_attempts_below_max_stay_pending(self):
        runner = orch.TaskRunner("t1")
        with mock.patch.object(runner, "_run_review_inner", side_effect=ValueError("boom")),              mock.patch("app.orchestrator.SessionLocal", _FakeSessionCtx),              mock.patch.object(runner, "_log", new=AsyncMock()):
            await runner._run_review("t1", "f2")
        self.assertEqual(runner._review_attempts.get("f2"), 1)
        self.assertIn("f2", runner._review_backoff)


if __name__ == "__main__":
    unittest.main()
