"""任务详情指挥横幅的后端支撑：统一进度视图 + 作战时间线。

运行：
  python -m unittest tests.test_board_deck -q
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.tasks import _progress_view, _timeline_buckets, task_timeline, _worker_phase, _worker_progress  # noqa: E402
from app.api.dto import TaskStats  # noqa: E402
from app.db.models import Base, Finding, Review, Target, Task  # noqa: E402


def _stats(**kw) -> TaskStats:
    s = TaskStats()
    for k, v in kw.items():
        setattr(s, k, v)
    return s


class ProgressViewTests(unittest.TestCase):
    def test_dispose_progress_from_targets(self):
        view = _progress_view("idle", _stats(queued=1, scanning=1, done=1, dead=1, skipped=1), {})
        self.assertEqual(view["kind"], "dispose")
        self.assertEqual(view["pct"], 60)  # 3/5

    def test_running_no_targets_is_collecting(self):
        view = _progress_view("running", _stats(), {})
        self.assertEqual(view["kind"], "collect")
        self.assertEqual(view["pct"], 25)  # 无阶段时的兜底

    def test_collect_phase_pct(self):
        cfg = {"collector_phase": "prefilter"}
        self.assertEqual(_progress_view("running", _stats(), cfg)["pct"], 18)
        cfg = {"collector_phase": "scoring"}
        self.assertEqual(_progress_view("running", _stats(), cfg)["pct"], 38)

    def test_enrich_uses_filter_ratio(self):
        cfg = {"collector_phase": "enrich", "last_target_filter_total": 10,
               "last_target_filter_evaluated": 5}
        view = _progress_view("running", _stats(), cfg)
        self.assertEqual(view["pct"], 72)  # 50% 落在 [72, 88] 下界
        self.assertEqual(view["meta"], "过滤器 5/10")

    def test_terminal_phase_switches_to_dispose(self):
        # 24×7 待命阶段（idle/dispatch/exhausted/fofa_error）：即便任务在跑，
        # 目标池已入队完成，进度必须回到处置口径而非停在搜集百分比。
        cfg = {"collector_phase": "idle"}
        view = _progress_view("running", _stats(done=3, queued=1), cfg)
        self.assertEqual(view["kind"], "dispose")
        self.assertEqual(view["pct"], 75)

    def test_phase_label_prefers_runtime_text(self):
        cfg = {"collector_phase": "prefilter", "collector_phase_text": "正在探活"}
        view = _progress_view("running", _stats(), cfg)
        self.assertEqual(view["phase_label"], "正在探活")
        cfg2 = {"collector_phase": "scoring"}
        self.assertEqual(_progress_view("running", _stats(), cfg2)["phase_label"], "评分归属")


class WorkerPhaseTests(unittest.TestCase):
    def test_found_wins_over_action(self):
        self.assertEqual(_worker_phase({"findings": 2, "action": "HTTP GET /x"}), "found")
        self.assertEqual(_worker_phase({"findings": 0, "action": "🎯 发现漏洞: SQL"}), "found")

    def test_verify_by_http_shell(self):
        self.assertEqual(_worker_phase({"action": "HTTP GET /api/user"}), "verify")
        self.assertEqual(_worker_phase({"action": "$ curl -s http://x"}), "verify")
        self.assertEqual(_worker_phase({"action": "查重: 未重复 xxx"}), "verify")

    def test_thinking_and_auth(self):
        self.assertEqual(_worker_phase({"action": "💭 分析响应"}), "thinking")
        self.assertEqual(_worker_phase({"action": "LLM 思考中…"}), "thinking")
        self.assertEqual(_worker_phase({"action": "凭据: 登录成功"}), "auth")
        self.assertEqual(_worker_phase({"action": "弱口令验证: http://x (admin)"}), "auth")
        self.assertEqual(_worker_phase({"action": "登录入口侦察: http://x"}), "auth")

    def test_booting_finishing_recon(self):
        self.assertEqual(_worker_phase({"action": "启动中…"}), "booting")
        self.assertEqual(_worker_phase({"action": "收尾: done"}), "finishing")
        self.assertEqual(_worker_phase({"action": "记录情报: dns"}), "recon")

    def test_progress_scales(self):
        self.assertEqual(_worker_progress({"round": 1, "findings": 0}), 6)
        self.assertEqual(_worker_progress({"round": 20, "findings": 0}), 50)
        self.assertEqual(_worker_progress({"round": 3, "findings": 1}), 67)
        self.assertEqual(_worker_progress({"round": 60, "findings": 5}), 100)


class TimelineBucketTests(unittest.TestCase):
    def test_fill_gaps_daily(self):
        items = [("2026-08-21", [2, 1]), ("2026-08-23", [1, 0])]
        out = _timeline_buckets(items, "day", 14)
        self.assertEqual([b["ts"] for b in out], ["2026-08-21", "2026-08-22", "2026-08-23"])
        self.assertEqual(out[1]["findings"], 0)

    def test_limit_takes_latest(self):
        items = [("2026-08-20", [1, 0]), ("2026-08-21", [2, 0]), ("2026-08-22", [3, 0])]
        out = _timeline_buckets(items, "day", 2)
        self.assertEqual([b["ts"] for b in out], ["2026-08-21", "2026-08-22"])

    def test_hour_span(self):
        items = [("2026-08-23 10", [1, 1]), ("2026-08-23 12", [1, 0])]
        out = _timeline_buckets(items, "hour", 14)
        self.assertEqual(len(out), 3)
        self.assertEqual(out[1]["findings"], 0)

    def test_empty(self):
        self.assertEqual(_timeline_buckets([], "day", 14), [])


class TimelineDbTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        db = Path(self._tmpdir.name) / "t.db"
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{db}", future=True)
        self.session_local = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def asyncTearDown(self):
        await self.engine.dispose()
        self._tmpdir.cleanup()

    async def _seed(self):
        # 东八区 2026-08-22 09:00 = UTC 01:00；08-23 10:00 = UTC 02:00
        async with self.session_local() as s:
            s.add(Task(id="t1", name="时间线", status="idle"))
            s.add(Target(id="g1", task_id="t1", url="https://a.edu.cn", host="a.edu.cn", status="done"))
            base = dict(task_id="t1", target_id="g1", vuln_type="sql_injection",
                        title="注入", severity_claimed="高危", target_url="https://a.edu.cn")
            f1 = Finding(id="f1", created_at=datetime(2026, 8, 22, 1, 0, tzinfo=timezone.utc), **base)
            f2 = Finding(id="f2", created_at=datetime(2026, 8, 23, 2, 0, tzinfo=timezone.utc), **base)
            f3 = Finding(id="f3", created_at=datetime(2026, 8, 23, 2, 30, tzinfo=timezone.utc), **base)
            f4 = Finding(id="f4", created_at=datetime(2026, 8, 23, 2, 40, tzinfo=timezone.utc),
                         status="superseded", **base)  # superseded 不计入
            s.add_all([f1, f2, f3, f4])
            s.add(Review(id="r1", finding_id="f2", task_id="t1", verdict="accepted",
                         confidence="confirmed", score=8.5))
            await s.commit()

    async def test_day_buckets_cst(self):
        await self._seed()
        async with self.session_local() as s:
            res = await task_timeline(task_id="t1", bucket="day", limit=14, session=s)
        by_ts = {b["ts"]: b for b in res["buckets"]}
        # UTC 08-22 01:00 → 北京 08-22 09:00（同日）；UTC 08-23 02:xx → 北京 08-23 10:xx
        self.assertEqual(by_ts["2026-08-22"]["findings"], 1)
        self.assertEqual(by_ts["2026-08-23"]["findings"], 2)
        self.assertEqual(by_ts["2026-08-23"]["accepted"], 1)
        self.assertEqual(res["total_findings"], 3)
        self.assertEqual(res["total_accepted"], 1)

    async def test_hour_buckets(self):
        await self._seed()
        async with self.session_local() as s:
            res = await task_timeline(task_id="t1", bucket="hour", limit=90, session=s)
        by_ts = {b["ts"]: b for b in res["buckets"]}
        self.assertEqual(by_ts["2026-08-23 10"]["findings"], 2)
        self.assertEqual(by_ts["2026-08-22 09"]["findings"], 1)

    async def test_task_not_found(self):
        from fastapi import HTTPException
        async with self.session_local() as s:
            with self.assertRaises(HTTPException):
                await task_timeline(task_id="nope", bucket="day", limit=14, session=s)


if __name__ == "__main__":
    unittest.main()
