"""知识库方法论映射测试：确认核心方法论（rule 类）能随触发词命中并注入。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.knowledge import _match_methods, _match_terms  # noqa: E402


class MatchMethodsTest(unittest.TestCase):
    def test_dig_scope_hits_asset_words(self):
        self.assertIn("dig-scope-workflow", _match_methods("资产"))
        self.assertIn("dig-scope-workflow", _match_methods("扩面 侦察"))

    def test_src_value_hits_priority_words(self):
        self.assertIn("src-value-hunting", _match_methods("高危优先级"))
        self.assertIn("src-value-hunting", _match_methods("类型矩阵"))

    def test_hunt_iter_hits_iteration_words(self):
        self.assertIn("hunt-iter", _match_methods("短表 复盘 换站"))

    def test_vuln_report_hits_report_words(self):
        self.assertIn("vuln-report-format", _match_methods("报告提交 复现"))
        self.assertIn("vuln-report-format", _match_methods("定级 poc"))

    def test_unrelated_no_vuln_words_no_method(self):
        # 纯越权/注入等漏洞类型词不误命中方法论（只命手册）
        self.assertEqual(_match_methods("越权"), [])
        self.assertEqual(_match_methods("sql注入 xss"), [])

    def test_non_matching_text_empty(self):
        self.assertEqual(_match_methods("随便什么没有触发词"), [])

    def test_graduate_school_not_research_method(self):
        # "研究生院" 不应误命中安全研究/白盒方法论
        self.assertEqual(_match_methods("研究生院"), [])


class MatchTermsEnglishTest(unittest.TestCase):
    """orchestrator 传入的英文漏洞类型（vuln_types）应命中对应手册。"""

    def test_english_vuln_types_map_to_manuals(self):
        self.assertIn("injection-test", _match_terms("rce"))
        self.assertIn("injection-test", _match_terms("ssti"))
        self.assertIn("authbypass-test", _match_terms("unauthorized_access"))
        self.assertIn("idor-test", _match_terms("privilege_escalation"))
        self.assertIn("recon-methodology", _match_terms("weak_password"))
        self.assertIn("file-upload-test", _match_terms("file_upload"))
        self.assertIn("path-traversal-lfi-test", _match_terms("file_read"))
        self.assertIn("info-leak-test", _match_terms("info_leak"))
        self.assertIn("logic-test", _match_terms("logic_flaw"))
        self.assertIn("open-redirect-test", _match_terms("open_redirect"))
        self.assertIn("waf-bypass", _match_terms("captcha_bypass"))

    def test_english_vuln_types_no_method(self):
        # 英文漏洞类型词不误命中方法论
        self.assertEqual(_match_methods("rce ssti info_leak"), [])


if __name__ == "__main__":
    unittest.main()