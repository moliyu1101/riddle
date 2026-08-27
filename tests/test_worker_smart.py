"""worker 智能化：经验知识引导注入、周期复盘开关、断点认知卡恢复。"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents import worker as worker_mod  # noqa: E402


def make_worker(meta=None):
    w = worker_mod.Worker.__new__(worker_mod.Worker)
    w.target = "https://example.com"
    w.target_meta = meta or {}
    w.findings = []
    w._emit = lambda *a, **k: None
    return w


class LessonsBlockTest(unittest.TestCase):
    def test_no_meta_no_lessons(self):
        w = make_worker({})
        self.assertEqual(w._lessons_block(), "")

    def test_spa_tag_matches_lesson(self):
        w = make_worker({"playbook_route": {"tags": ["vue", "spa", "api_exposed"], "label": "SPA"}})
        block = w._lessons_block()
        self.assertIn("经验引导", block)
        self.assertIn("SPA", block)

    def test_unrelated_no_lesson(self):
        w = make_worker({"playbook_route": {"tags": ["static", "index"], "label": "静态"}})
        self.assertEqual(w._lessons_block(), "")


class ReflectConstantTest(unittest.TestCase):
    def test_reflect_every_positive(self):
        self.assertGreater(worker_mod.REFLECT_EVERY, 0)
        self.assertTrue(hasattr(worker_mod, "_REFLECT_PROMPT"))
        self.assertIn("update_cognition", worker_mod._REFLECT_PROMPT)

    def test_reflect_injected_on_schedule(self):
        # 验证复盘点判定逻辑（rounds 已自增的循环语义）
        for r in (8, 16, 24):
            self.assertTrue(r > 0 and r % worker_mod.REFLECT_EVERY == 0)
        for r in (1, 3, 7, 9):
            self.assertFalse(r > 0 and r % worker_mod.REFLECT_EVERY == 0 and r % worker_mod.REFLECT_EVERY == worker_mod.REFLECT_EVERY - 3)


class ResumeCognitionTest(unittest.TestCase):
    def test_resume_context_carries_cognition(self):
        class FakeExecutor:
            def export_resume_state(self):
                return {
                    "worker_notes": "",
                    "cognition": {"confirmed": ["能读他人档案"], "excluded": [], "leads": [], "plan": "打 /admin"},
                    "session_cookies": {}, "session_headers": {},
                }
        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        ctx = w._build_resume_context(rounds=3)
        self.assertEqual(ctx["cognition"]["confirmed"], ["能读他人档案"])

    def test_no_progress_returns_empty(self):
        class FakeExecutor:
            def export_resume_state(self):
                return {"worker_notes": "", "session_cookies": {}, "session_headers": {}, "cognition": {}}
        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        self.assertEqual(w._build_resume_context(rounds=0), {})

    def test_resume_carries_probed_urls(self):
        # 已探测 URL 随断点保存，且写入 directive 避免恢复后重复探测
        class FakeExecutor:
            def export_resume_state(self):
                return {
                    "worker_notes": "已确认登录接口",
                    "cognition": {}, "session_cookies": {}, "session_headers": {},
                }
        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        w._probed_urls = {"https://example.com/api/login", "https://example.com/api/user"}
        ctx = w._build_resume_context(rounds=3)
        self.assertIn("https://example.com/api/login", ctx["probed_urls"])
        self.assertIn("https://example.com/api/user", ctx["probed_urls"])
        self.assertIn("已探测过的 URL", ctx["directive"])
        self.assertIn("https://example.com/api/login", ctx["directive"])

    def test_restore_recovers_probed_urls(self):
        # 恢复时把上一轮探测过的 URL 灌回 worker，避免从头泛扫
        class FakeExecutor:
            def restore_resume_state(self, **kw):
                pass
        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        w.deepen_context = {
            "source": "llm_interrupt",
            "worker_notes": "n",
            "probed_urls": ["https://example.com/api/login", "https://example.com/api/user"],
        }
        w._emit = Mock()
        w._restore_interrupt_progress()
        self.assertIn("https://example.com/api/login", w._probed_urls)
        self.assertIn("https://example.com/api/user", w._probed_urls)
        self.assertEqual(w._emit.call_args.args[0], "worker_resume")
        self.assertEqual(w._emit.call_args.kwargs["probed_urls"], 2)

    def test_deepen_brief_lists_probed_urls(self):
        # 断点续挖的提示里带上已探测 URL，明确要求不要重复请求
        w = make_worker()
        w._probed_urls = {"https://example.com/api/login"}
        w.deepen_context = {"source": "llm_interrupt", "directive": "继续打 /api/admin"}
        brief = w._deepen_brief()
        self.assertIn("断点续挖", brief)
        self.assertIn("https://example.com/api/login", brief)
        self.assertIn("不要再重复请求", brief)


if __name__ == "__main__":
    unittest.main()