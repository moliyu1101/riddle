"""Blackboard 黑板机制测试：单站协作多 Worker 实时共享信息、避免重复路线。

覆盖：
- Blackboard 核心：publish/query/declare/note_probed/add_coverage/add_lead/add_excluded
- summary 渲染（注入 prompt 的协作态势）、snapshot（前端用）、条目上限、并发安全
- Worker 集成：blackboard_publish/query/declare 工具分发、http_request 自动发布 probed、
  _blackboard_block 注入、blackboard=None 完全降级
- Orchestrator 集成：TaskRunner 黑板懒创建
"""
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.blackboard import Blackboard  # noqa: E402
from app.agents.worker import Worker  # noqa: E402


def _make_worker(blackboard=None, worker_id="w1"):
    events = []
    w = Worker(
        "https://example.edu.cn/",
        llm=Mock(),
        on_event=lambda kind, data: events.append((kind, data)),
        src_type="edusrc",
        blackboard=blackboard,
        worker_id=worker_id,
    )
    return w, events


class BlackboardCoreTest(unittest.TestCase):
    def setUp(self):
        self.bb = Blackboard("task-1")

    def test_publish_and_query(self):
        r = self.bb.publish("lead", "GET /api/export 未授权可导出", "w1", "high")
        self.assertTrue(r["ok"])
        out = self.bb.query("lead")
        self.assertEqual(len(out["entries"]), 1)
        self.assertEqual(out["entries"][0]["value"], "GET /api/export 未授权可导出")
        self.assertEqual(out["entries"][0]["confidence"], "high")

    def test_publish_requires_key_and_value(self):
        self.assertFalse(self.bb.publish("", "x", "w1")["ok"])
        self.assertFalse(self.bb.publish("k", "", "w1")["ok"])

    def test_query_overview(self):
        self.bb.publish("lead", "a", "w1")
        self.bb.note_probed("https://x/1", "w1")
        out = self.bb.query()
        self.assertEqual(out["keys"], {"lead": 1})
        self.assertEqual(out["probed"], 1)

    def test_declare_direction(self):
        self.assertTrue(self.bb.declare("测认证越权", "w1")["ok"])
        self.assertEqual(self.bb._directions["w1"], "测认证越权")
        self.assertFalse(self.bb.declare("", "w1")["ok"])

    def test_note_probed_dedup_and_cap(self):
        for i in range(Blackboard.MAX_PROBED + 20):
            self.bb.note_probed(f"https://x/{i}", "w1")
        self.assertLessEqual(len(self.bb._probed), Blackboard.MAX_PROBED)
        self.bb.note_probed("https://x/1", "w1")
        self.assertEqual(len(self.bb._probed), Blackboard.MAX_PROBED)

    def test_add_coverage_lead_excluded_cap(self):
        for i in range(Blackboard.MAX_COVERAGE + 5):
            self.bb.add_coverage({"summary": f"c{i}"}, "w1")
        self.assertLessEqual(len(self.bb._coverage), Blackboard.MAX_COVERAGE)
        for i in range(Blackboard.MAX_LEADS + 5):
            self.bb.add_lead(f"lead{i}", "w1")
        self.assertLessEqual(len(self.bb._leads), Blackboard.MAX_LEADS)
        for i in range(Blackboard.MAX_EXCLUDED + 5):
            self.bb.add_excluded(f"ex{i}", "w1")
        self.assertLessEqual(len(self.bb._excluded), Blackboard.MAX_EXCLUDED)

    def test_summary_empty_when_blank(self):
        self.assertEqual(self.bb.summary(), "")

    def test_summary_renders_sections(self):
        self.bb.declare("测认证越权", "w1")
        self.bb.note_probed("https://x/login", "w1")
        self.bb.add_coverage({"summary": "GET /api/users 需登录", "endpoints": []}, "w1")
        self.bb.add_lead("导出接口未授权", "w1", "high")
        self.bb.add_excluded("/api/health 无洞", "w1")
        text = self.bb.summary(worker_id="w1")
        self.assertIn("协作黑板", text)
        self.assertIn("当前分工", text)
        self.assertIn("已探测 URL", text)
        self.assertIn("已覆盖入口", text)
        self.assertIn("共享线索", text)
        self.assertIn("已排除", text)

    def test_snapshot_shape(self):
        self.bb.declare("方向A", "w1")
        self.bb.note_probed("https://x/1", "w1")
        snap = self.bb.snapshot()
        self.assertEqual(snap["task_id"], "task-1")
        self.assertEqual(snap["directions"], {"w1": "方向A"})
        self.assertIn("https://x/1", [p["url"] for p in snap["probed"]])
        self.assertEqual(snap["probed"][0]["source"], "")
        self.assertIn("events", snap)

    def test_concurrent_publish_is_safe(self):
        errors = []

        def worker(n):
            try:
                for i in range(50):
                    self.bb.publish("k", f"v{n}-{i}", f"w{n}", "medium")
                    self.bb.note_probed(f"https://x/{n}/{i}", f"w{n}")
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.bb._entries["k"]), 400)
        # note_probed 有 MAX_PROBED 上限，超限淘汰最旧
        self.assertEqual(len(self.bb._probed), Blackboard.MAX_PROBED)


class WorkerBlackboardIntegrationTest(unittest.TestCase):
    def test_dispatch_blackboard_publish(self):
        bb = Blackboard("task-1")
        w, events = _make_worker(bb, "w1")
        r = w._dispatch("blackboard_publish", {"key": "lead", "value": "发现导出接口", "confidence": "high"}, 1)
        self.assertTrue(r["ok"])
        self.assertEqual(len(bb.query("lead")["entries"]), 1)
        kinds = [k for k, _ in events]
        self.assertIn("blackboard_publish", kinds)

    def test_dispatch_blackboard_query(self):
        bb = Blackboard("task-1")
        bb.publish("lead", "x", "w2")
        w, _ = _make_worker(bb, "w1")
        out = w._dispatch("blackboard_query", {"key": "lead"}, 1)
        self.assertTrue(out["ok"])
        self.assertEqual(len(out["entries"]), 1)

    def test_dispatch_blackboard_declare(self):
        bb = Blackboard("task-1")
        w, events = _make_worker(bb, "w1")
        r = w._dispatch("blackboard_declare", {"direction": "测认证越权"}, 1)
        self.assertTrue(r["ok"])
        self.assertEqual(bb._directions["w1"], "测认证越权")
        self.assertIn("blackboard_declare", [k for k, _ in events])

    def test_http_request_auto_publishes_probed(self):
        bb = Blackboard("task-1")
        w, _ = _make_worker(bb, "w1")

        class FakeExec:
            def http_request(self, **kw):
                return {"ok": True, "status_code": 200, "body": "<html></html>",
                        "response_headers": {}, "title": ""}

        w.executor = FakeExec()
        w._dispatch("http_request", {"url": "https://example.edu.cn/api/login"}, 1)
        self.assertIn("https://example.edu.cn/api/login", bb._probed)

    def test_blackboard_block_injected(self):
        bb = Blackboard("task-1")
        bb.declare("测认证越权", "w2")
        bb.note_probed("https://x/1", "w2")
        w, _ = _make_worker(bb, "w1")
        block = w._blackboard_block()
        self.assertIn("协作黑板", block)
        self.assertIn("测认证越权", block)
        self.assertIn("https://x/1", block)

    def test_blackboard_none_degrades(self):
        w, _ = _make_worker(None, "w1")
        self.assertEqual(w._blackboard_block(), "")
        r = w._dispatch("blackboard_publish", {"key": "k", "value": "v"}, 1)
        self.assertFalse(r["ok"])
        self.assertIn("未启用", r["error"])
        r2 = w._dispatch("blackboard_query", {}, 1)
        self.assertFalse(r2["ok"])

    def test_blackboard_tools_not_in_default_schema(self):
        from app.tools.schemas import TOOL_SCHEMAS
        names = {s["function"]["name"] for s in TOOL_SCHEMAS}
        self.assertIn("blackboard_publish", names)
        self.assertIn("blackboard_query", names)
        self.assertIn("blackboard_declare", names)


class OrchestratorBlackboardTest(unittest.TestCase):
    def test_runner_lazy_creates_blackboard(self):
        from app.orchestrator import TaskRunner
        runner = TaskRunner("task-1")
        self.assertIsNone(runner._blackboard)
        bb = runner._get_blackboard()
        self.assertIsNotNone(bb)
        self.assertEqual(bb.task_id, "task-1")
        self.assertIs(runner._get_blackboard(), bb)


if __name__ == "__main__":
    unittest.main()
