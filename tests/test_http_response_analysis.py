"""http_request 响应自动分析测试。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402


class JsonFieldNamesTest(unittest.TestCase):
    def test_top_level_fields(self):
        fields = ToolExecutor._json_field_names({"id": 1, "name": "x", "token": "t"})
        self.assertEqual(fields, ["id", "name", "token"])

    def test_list_of_dicts(self):
        fields = ToolExecutor._json_field_names([{"a": 1, "b": 2}, {"a": 3}])
        self.assertEqual(fields, ["a", "b"])

    def test_nested_dict(self):
        fields = ToolExecutor._json_field_names({"data": {"uid": 1, "role": "admin"}})
        self.assertEqual(fields, ["data"])

    def test_scalar_returns_empty(self):
        self.assertEqual(ToolExecutor._json_field_names(42), [])
        self.assertEqual(ToolExecutor._json_field_names("str"), [])

    def test_field_cap(self):
        big = {f"k{i}": i for i in range(50)}
        fields = ToolExecutor._json_field_names(big)
        self.assertLessEqual(len(fields), ToolExecutor._JSON_FIELD_MAX)


class AnalyzeHttpResponseTest(unittest.TestCase):
    def test_json_fields_detected(self):
        body = '{"code":0,"data":{"users":[{"id":1,"phone":"13800138000"}]}}'
        analysis = ToolExecutor._analyze_http_response(body, {})
        self.assertEqual(analysis["json_fields"], ["code", "data"])
        self.assertIn("phone", analysis.get("sensitive_hits", []))

    def test_id_card_detected(self):
        body = '{"idCard":"110101199003077777"}'
        analysis = ToolExecutor._analyze_http_response(body, {})
        self.assertIn("id_card", analysis.get("sensitive_hits", []))

    def test_phone_detected(self):
        body = '{"mobile":"13912345678"}'
        analysis = ToolExecutor._analyze_http_response(body, {})
        self.assertIn("phone", analysis.get("sensitive_hits", []))

    def test_secret_keyword_detected(self):
        body = '{"accessKey":"AKIA1234567890"}'
        analysis = ToolExecutor._analyze_http_response(body, {})
        self.assertIn("secret_or_token", analysis.get("sensitive_hits", []))

    def test_tech_from_headers(self):
        analysis = ToolExecutor._analyze_http_response(
            "<html>ok</html>", {"Server": "nginx/1.20", "X-Powered-By": "PHP/7.4"},
        )
        self.assertTrue(any("nginx" in t for t in analysis.get("tech", [])))
        self.assertTrue(any("PHP" in t for t in analysis.get("tech", [])))

    def test_tech_from_body_marker(self):
        analysis = ToolExecutor._analyze_http_response(
            '<html>ThinkPHP v5.0</html>', {},
        )
        self.assertIn("ThinkPHP", analysis.get("tech", []))

    def test_plain_html_no_analysis(self):
        analysis = ToolExecutor._analyze_http_response("<html>hello world</html>", {})
        self.assertEqual(analysis, {})

    def test_invalid_json_no_crash(self):
        analysis = ToolExecutor._analyze_http_response("not json {{{{", {})
        self.assertNotIn("json_fields", analysis)


if __name__ == "__main__":
    unittest.main()
