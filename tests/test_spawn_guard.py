"""double_spawn 防护回归：同目标已有未结束协程时跳过重复派发，不再覆盖引用。"""
import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.orchestrator import TaskRunner  # noqa: E402


class DoubleSpawnGuardTest(unittest.TestCase):
    def test_spawn_skipped_when_prev_alive(self):
        """prev 未结束 → 跳过派发，_active_workers 保留旧协程引用不被覆盖。"""

        async def main():
            runner = TaskRunner("task-x")
            blocker = asyncio.create_task(asyncio.sleep(3600))
            runner._active_workers["t1"] = blocker
            runner._spawn_worker(
                SimpleNamespace(id="task-x"),
                SimpleNamespace(id="t1", url="http://x.example.com"),
            )
            try:
                self.assertIs(runner._active_workers["t1"], blocker)
                self.assertNotIn("t1", runner._worker_cancel_events)
            finally:
                blocker.cancel()
                with __import__("contextlib").suppress(asyncio.CancelledError):
                    await blocker

        asyncio.run(main())

    def test_spawn_proceeds_when_prev_done(self):
        """prev 已结束 → 正常重派（新建 cancel_event，覆盖引用）。"""

        async def main():
            runner = TaskRunner("task-x")
            done = asyncio.create_task(asyncio.sleep(0))
            await done
            runner._active_workers["t1"] = done
            # 不真正执行 _run_worker（会连 DB/LLM）：只验证分支放行到 create_task 之前
            # 的状态变化——cancel_event 已注册。
            target = SimpleNamespace(id="t1", url="http://x.example.com")

            import unittest.mock as mock

            with mock.patch.object(runner, "_run_worker", new=mock.AsyncMock(return_value=None)):
                runner._spawn_worker(SimpleNamespace(id="task-x"), target)
                t = runner._active_workers["t1"]
                self.assertIsNot(t, done)
                self.assertIn("t1", runner._worker_cancel_events)
                t.cancel()
                with __import__("contextlib").suppress(asyncio.CancelledError):
                    await t

        asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
