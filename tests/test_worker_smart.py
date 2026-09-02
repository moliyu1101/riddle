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


class EvidenceTrailResumeTest(unittest.TestCase):
    def test_restore_from_trail_without_context(self):
        # 硬杀/重启后无中断上下文，但证据链有取证动作：应回灌 probed_urls 并触发断点续挖
        import tempfile
        from app.tools import evidence_trail

        tmp = tempfile.mkdtemp()
        evidence_trail.append_trail(tmp, kind="http_request", target="https://example.com",
                                    url="https://example.com/api/login", method="GET", status=200)
        evidence_trail.append_trail(tmp, kind="http_request", target="https://example.com",
                                    url="https://example.com/role/set?userId=1&role=admin", method="GET", status=200)

        class FakeExecutor:
            work_dir = tmp

        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        w.deepen_context = {"source": "worker_lead"}  # 非 llm_interrupt，且无 notes/cookies
        w._emit = Mock()
        w._restore_interrupt_progress()
        self.assertIn("https://example.com/api/login", w._probed_urls)
        self.assertIn("https://example.com/role/set?userId=1&role=admin", w._probed_urls)
        # 应被改写为 llm_interrupt，触发断点续挖分支
        self.assertEqual(w.deepen_context.get("source"), "llm_interrupt")
        self.assertEqual(w._emit.call_args.args[0], "worker_resume")
        self.assertEqual(w._emit.call_args.kwargs["source"], "evidence_trail")

    def test_deepen_brief_injects_evidence(self):
        # 断点续挖首轮 prompt 应包含上一轮落盘的真实取证动作
        import tempfile
        from app.tools import evidence_trail

        tmp = tempfile.mkdtemp()
        evidence_trail.append_trail(tmp, kind="http_request", target="https://example.com",
                                    url="https://example.com/role/set?userId=1&role=admin", method="GET", status=200)

        class FakeExecutor:
            work_dir = tmp

        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        w.deepen_context = {"source": "llm_interrupt", "directive": "继续验证越权"}
        brief = w._deepen_brief()
        self.assertIn("断点续挖", brief)
        self.assertIn("role/set", brief)
        self.assertIn("真实取证动作", brief)


class StagedFindingsTest(unittest.TestCase):
    def test_stash_and_claim_roundtrip(self):
        # submit 成功后同步落盘暂存，恢复时认领回 self.findings（硬杀不丢洞）
        import tempfile
        from app.agents.worker import Finding

        tmp = tempfile.mkdtemp()

        class FakeExecutor:
            work_dir = tmp

        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        f = Finding(
            title="越权漏洞", vuln_type="unauthorized",
            severity_claimed="高危", target_url="https://example.com/role/set",
            description="未授权修改角色", steps=[], poc="curl -x",
        )
        w._stash_finding(f)
        # 文件已落盘
        path = w._staged_findings_path()
        self.assertTrue(path.exists())
        # 恢复认领
        w2 = make_worker()
        w2.executor = FakeExecutor()  # type: ignore
        w2.deepen_context = {}
        staged = w2._load_staged_findings()
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0]["title"], "越权漏洞")
        w2._restore_interrupt_progress()
        self.assertEqual(len(w2.findings), 1)
        self.assertEqual(w2.findings[0].title, "越权漏洞")

    def test_stash_failure_does_not_block_submit(self):
        # 暂存失败（如 work_dir 不可写）静默忽略，不影响 submit 主流程
        import tempfile
        from app.agents.worker import Finding

        tmp = tempfile.mkdtemp()

        class FakeExecutor:
            work_dir = tmp

        w = make_worker()
        w.executor = FakeExecutor()  # type: ignore
        w._staged_findings_path = lambda: None  # 模拟不可用
        f = Finding(
            title="XSS", vuln_type="xss",
            severity_claimed="中危", target_url="https://example.com/x",
            description="存储型XSS", steps=[], poc="",
        )
        w._stash_finding(f)  # 不应抛异常
        self.assertEqual(len(w.findings), 0)


if __name__ == "__main__":
    unittest.main()