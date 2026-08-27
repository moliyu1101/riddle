"""审核反馈闭环测试：把初审 accepted/ignored 结论沉淀为 lesson 情报并回流。

覆盖：distill_review_lesson 提炼规则（正向 PoC/负向易踩坑/过滤无价值）、
assess_intel 对 lesson 的放行与校验、render_intel_block 的 lesson 渲染、emit_review_lessons 接线。
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.intel import (  # noqa: E402
    distill_review_lesson,
    emit_review_lessons,
    render_intel_block,
)
from app.agents.intel_curator import assess_intel  # noqa: E402
from app.db.models import Intel  # noqa: E402

FP = {
    "vuln_type": "越权",
    "title": "教务系统成绩查询越权",
    "target_url": "https://jwgl.example.edu.cn/api/score",
    "owner": "示例大学",
    "poc": "GET /api/score?sid=2 返回他人成绩",
    "raw_request": "GET /api/score?sid=2 HTTP/1.1",
}


class DistillTest(unittest.TestCase):
    def test_accepted_produces_poc_verified(self):
        item = distill_review_lesson(FP, {"verdict": "accepted", "confidence": "confirmed",
                                          "severity_final": "高危"})
        self.assertIsNotNone(item)
        self.assertEqual(item["kind"], "lesson")
        self.assertEqual(item["confidence"], "verified")
        self.assertEqual(item["payload"]["lesson_type"], "poc")
        self.assertEqual(item["payload"]["vuln_type"], "越权")
        self.assertTrue(item["payload"].get("repro"))
        self.assertIn("已出洞打法", item["summary"])
        self.assertEqual(item["match_key"], "edu_jwgl")  # 教务系统指纹

    def test_ignored_evidence_reason_produces_pitfall(self):
        item = distill_review_lesson(FP, {"verdict": "ignored",
                                          "ignore_reasons": ["半成品", "证据不足"]})
        self.assertIsNotNone(item)
        self.assertEqual(item["payload"]["lesson_type"], "pitfall")
        self.assertIn("易踩坑", item["summary"])
        self.assertEqual(item["confidence"], "likely")

    def test_ignored_scope_reason_not_distilled(self):
        item = distill_review_lesson(FP, {"verdict": "ignored",
                                          "ignore_reasons": ["不在教育范围", "外站链接"]})
        self.assertIsNone(item)

    def test_deepen_not_distilled(self):
        self.assertIsNone(distill_review_lesson(FP, {"verdict": "deepen"}))

    def test_no_fingerprint_not_distilled(self):
        f = dict(FP, target_url="https://random-site.example.com/page",
                 title="普通页面", owner="")
        self.assertIsNone(distill_review_lesson(f, {"verdict": "accepted"}))


class AssessLessonTest(unittest.TestCase):
    def test_ok_poc(self):
        a = assess_intel("lesson", "edu_jwgl", {"lesson_type": "poc", "vuln_type": "越权",
                                                "repro": "GET /api?sid=2 返回他人成绩"}, "已出洞打法", "verified")
        self.assertTrue(a.ok)

    def test_ok_pitfall(self):
        a = assess_intel("lesson", "edu_jwgl", {"lesson_type": "pitfall", "vuln_type": "越权",
                                                "reason": "半成品证据不足"}, "", "likely")
        self.assertTrue(a.ok)

    def test_bad_poc_too_short(self):
        a = assess_intel("lesson", "edu_jwgl", {"lesson_type": "poc", "vuln_type": "越权"}, "", "verified")
        self.assertFalse(a.ok)

    def test_bad_pitfall_no_reason(self):
        a = assess_intel("lesson", "edu_jwgl", {"lesson_type": "pitfall", "vuln_type": "越权"}, "", "likely")
        self.assertFalse(a.ok)

    def test_bad_lesson_type(self):
        a = assess_intel("lesson", "edu_jwgl", {"lesson_type": "nope", "vuln_type": "越权",
                                                "repro": "x" * 20, "reason": "x"}, "s", "likely")
        self.assertFalse(a.ok)


class RenderLessonTest(unittest.TestCase):
    def test_renders_poc_lesson(self):
        it = Intel(kind="lesson", match_key="edu_jwgl", confidence="verified",
                   summary="已出洞打法 [越权] 教务成绩", payload={"lesson_type": "poc", "vuln_type": "越权"})
        block = render_intel_block({"lesson": [it]})
        self.assertIn("同类系统历史经验", block)
        self.assertIn("有效打法", block)
        self.assertIn("已出洞打法", block)

    def test_empty_when_no_lesson_kind(self):
        it = Intel(kind="fingerprint", match_key="edu_jwgl", confidence="verified",
                   summary="打法", payload={"tactic": "xxx", "vuln_type": "SQLi"})
        block = render_intel_block({"fingerprint": [it]})
        self.assertNotIn("同类系统历史经验", block)
        self.assertIn("同类系统打法", block)


class EmitTest(unittest.TestCase):
    @patch("app.agents.intel.record_intel")
    def test_emit_records_accepted(self, mock_record):
        mock_record.return_value = True
        asyncio.run(emit_review_lessons(None, dict(FP), {"verdict": "accepted", "severity_final": "高危"}))
        self.assertEqual(mock_record.call_count, 1)
        kwargs = mock_record.call_args.kwargs
        self.assertEqual(mock_record.call_args[0][1], "lesson")
        self.assertEqual(mock_record.call_args[0][2], "edu_jwgl")
        self.assertEqual(kwargs["payload"]["lesson_type"], "poc")

    @patch("app.agents.intel.record_intel")
    def test_emit_skips_deepen(self, mock_record):
        asyncio.run(emit_review_lessons(None, dict(FP), {"verdict": "deepen"}))
        mock_record.assert_not_called()


if __name__ == "__main__":
    unittest.main()