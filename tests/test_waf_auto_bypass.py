"""http_request 自动 WAF 绕过测试：检测到 WAF 拦截时自动重试无害变体。"""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402


class _WafHandler(BaseHTTPRequestHandler):
    mode = "bypass_ok"  # bypass_ok / bypass_fail / plain_403 / ok

    def do_GET(self):  # noqa: N802
        self._serve()

    def do_POST(self):  # noqa: N802
        self._serve()

    def _serve(self):
        if self.mode == "ok":
            self._send(200, "hello world")
            return
        if self.mode == "plain_403":
            self._send(403, "Forbidden - you lack permission")
            return
        if self.mode == "bypass_fail":
            self._send(403, "Access Denied by WAF - blocked")
            return
        # bypass_ok：带 X-Forwarded-For 的变体放行，其余拦截
        if self.headers.get("X-Forwarded-For") == "127.0.0.1":
            self._send(200, "OK bypassed")
        else:
            self._send(403, "Access Denied by WAF - blocked")

    def _send(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # 静默
        pass


class WafAutoBypassTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _WafHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _exec(self, mode: str) -> ToolExecutor:
        _WafHandler.mode = mode
        return ToolExecutor(target=f"http://127.0.0.1:{self.port}")

    def test_bypass_ok_returns_bypassed_result(self):
        ex = self._exec("bypass_ok")
        r = ex.http_request(f"http://127.0.0.1:{self.port}/api/login?user=admin' or '1'='1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 200)
        self.assertIn("OK bypassed", r["body"])
        self.assertTrue(r["waf"]["detected"])
        self.assertTrue(r["waf"]["bypassed"])
        self.assertEqual(r["waf"]["original_status"], 403)
        self.assertIn("X-Forwarded-For", r["waf"]["technique"])

    def test_bypass_fail_returns_original_with_waf_info(self):
        ex = self._exec("bypass_fail")
        r = ex.http_request(f"http://127.0.0.1:{self.port}/api/login?user=admin")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 403)
        self.assertTrue(r["waf"]["detected"])
        self.assertFalse(r["waf"]["bypassed"])
        self.assertTrue(r["waf"]["tried"])

    def test_plain_403_does_not_trigger_auto_bypass(self):
        ex = self._exec("plain_403")
        r = ex.http_request(f"http://127.0.0.1:{self.port}/api/private")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 403)
        self.assertNotIn("waf", r)

    def test_normal_200_no_waf_field(self):
        ex = self._exec("ok")
        r = ex.http_request(f"http://127.0.0.1:{self.port}/")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 200)
        self.assertNotIn("waf", r)

    def test_url_encode_query_variant(self):
        self.assertEqual(
            ToolExecutor._url_encode_query("http://x/a?user=admin' or '1'='1"),
            "http://x/a?user=admin%27+or+%271%27%3D%271",
        )
        self.assertEqual(ToolExecutor._url_encode_query("http://x/a"), "http://x/a")

    def test_form_encode_variant(self):
        self.assertEqual(
            ToolExecutor._url_encode_form("user=admin' or '1'='1&pass=x"),
            "user=admin%27+or+%271%27%3D%271&pass=x",
        )

    def test_is_waf_blocked_generic_needs_two_keywords(self):
        self.assertTrue(ToolExecutor._is_waf_blocked(403, {}, "Access Denied by WAF - blocked"))
        self.assertFalse(ToolExecutor._is_waf_blocked(403, {}, "Forbidden - you lack permission"))
        self.assertFalse(ToolExecutor._is_waf_blocked(200, {}, "hello"))
        self.assertTrue(ToolExecutor._is_waf_blocked(403, {"cf-ray": "abc"}, "whatever"))


if __name__ == "__main__":
    unittest.main()
