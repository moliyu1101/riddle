"""Reviewer 复现验证确定性信号测试。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.reviewer import (  # noqa: E402
    _extract_reproduce_signals,
    _poc_is_executable,
    _reproduce_deterministic_verdict,
)


class PocExecutableTest(unittest.TestCase):
    def test_curl_is_executable(self):
        self.assertTrue(_poc_is_executable("curl -X POST http://target/api -d 'a=1'"))

    def test_python_is_executable(self):
        self.assertTrue(_poc_is_executable("python3 -c 'print(1)'"))

    def test_sql_payload_not_executable(self):
        self.assertFalse(_poc_is_executable("' OR 1=1 --"))

    def test_path_traversal_not_executable(self):
        self.assertFalse(_poc_is_executable("../../etc/passwd"))

    def test_script_tag_not_executable(self):
        self.assertFalse(_poc_is_executable("<script>alert(1)</script>"))

    def test_empty_not_executable(self):
        self.assertFalse(_poc_is_executable(""))

    def test_multiline_curl_executable(self):
        poc = "curl -X POST http://target/api\n  -H 'Content-Type: application/json'\n  -d '{}'"
        self.assertTrue(_poc_is_executable(poc))


class ExtractSignalsTest(unittest.TestCase):
    def test_status_codes_extracted(self):
        out = "HTTP/1.1 200 OK\nHTTP/2 403 Forbidden\n"
        sig = _extract_reproduce_signals(out)
        self.assertEqual(sig["status_codes"], [200, 403])
        self.assertFalse(sig["output_empty"])

    def test_sql_error_detected(self):
        out = "You have an error in your SQL syntax; check the manual"
        sig = _extract_reproduce_signals(out)
        self.assertTrue(sig["has_sql_error"])

    def test_rce_output_detected(self):
        out = "uid=0(root) gid=0(root) groups=0(root)"
        sig = _extract_reproduce_signals(out)
        self.assertTrue(sig["has_rce_output"])

    def test_time_extracted_from_real(self):
        out = "real\t0m5.23s\nuser\t0m0.01s"
        sig = _extract_reproduce_signals(out)
        self.assertAlmostEqual(sig["elapsed_seconds"], 5.23, places=2)

    def test_time_extracted_from_curl_total(self):
        out = "time_total: 7.891000"
        sig = _extract_reproduce_signals(out)
        self.assertAlmostEqual(sig["elapsed_seconds"], 7.891, places=3)

    def test_empty_output(self):
        sig = _extract_reproduce_signals("   \n  ")
        self.assertTrue(sig["output_empty"])

    def test_error_page_detected(self):
        sig = _extract_reproduce_signals("<title>500 Internal Server Error</title>")
        self.assertTrue(sig["error_page"])


class DeterministicVerdictTest(unittest.TestCase):
    def test_empty_output_is_fail(self):
        sig = _extract_reproduce_signals("")
        reproduced, reason = _reproduce_deterministic_verdict(sig, "sql_injection", "注入")
        self.assertFalse(reproduced)
        self.assertIn("无任何输出", reason)

    def test_5xx_is_fail(self):
        sig = _extract_reproduce_signals("HTTP/1.1 500 Internal Server Error")
        reproduced, _ = _reproduce_deterministic_verdict(sig, "unauthorized_access", "越权")
        self.assertFalse(reproduced)

    def test_sql_error_is_positive(self):
        sig = _extract_reproduce_signals("SQLSTATE[42000]: Syntax error near '1'")
        reproduced, reason = _reproduce_deterministic_verdict(sig, "sql_injection", "SQL 注入")
        self.assertTrue(reproduced)
        self.assertIn("数据库报错", reason)

    def test_sql_error_not_positive_for_other_types(self):
        # SQL 报错出现在非注入类漏洞里，不当作强正信号（交给 LLM 判断）
        sig = _extract_reproduce_signals("SQLSTATE[42000]: Syntax error")
        reproduced, _ = _reproduce_deterministic_verdict(sig, "idor", "越权")
        self.assertIsNone(reproduced)

    def test_rce_output_is_positive(self):
        sig = _extract_reproduce_signals("uid=33(www-data) gid=33(www-data)")
        reproduced, reason = _reproduce_deterministic_verdict(sig, "rce", "命令执行")
        self.assertTrue(reproduced)
        self.assertIn("命令执行回显", reason)

    def test_time_blind_is_positive(self):
        sig = _extract_reproduce_signals("real\t0m4.50s")
        reproduced, reason = _reproduce_deterministic_verdict(sig, "sql_injection", "时间盲注")
        self.assertTrue(reproduced)
        self.assertIn("延时", reason)

    def test_short_time_is_indeterminate(self):
        sig = _extract_reproduce_signals("real\t0m0.8s")
        reproduced, _ = _reproduce_deterministic_verdict(sig, "sql_injection", "时间盲注")
        self.assertIsNone(reproduced)

    def test_normal_200_is_indeterminate(self):
        # 200 + 正常响应体：无法确定是否复现，交给 LLM 判断
        sig = _extract_reproduce_signals("HTTP/1.1 200 OK\n<html>hello</html>")
        reproduced, _ = _reproduce_deterministic_verdict(sig, "idor", "越权")
        self.assertIsNone(reproduced)


if __name__ == "__main__":
    unittest.main()
