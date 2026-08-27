"""专项漏洞探测工具测试：sqli_probe / upload_probe / access_boundary 纯规则逻辑。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.probe_tools import (  # noqa: E402
    _SQL_ERROR_MARKERS,
    _has_sql_error,
    _replace_param,
    access_boundary,
    sqli_probe,
    upload_probe,
)


def _resp(status=200, body="", body_len=None):
    return {"ok": True, "status_code": status, "body": body,
            "body_len": len(body) if body_len is None else body_len}


class FakeExecutor:
    """可编程 mock：按调用序号返回预设响应，并记录调用参数。"""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
        self._session_cookies = {"SID": "abc"}
        self._session_headers = {"X-Token": "t1"}

    def http_request(self, url, method="GET", headers=None, data=None, timeout=20, **kw):
        self.calls.append({"url": url, "method": method, "data": data})
        if self.responses:
            return self.responses.pop(0)
        return _resp()

    def session_set(self, clear=False, cookies=None, headers=None, **kw):
        if clear:
            self._session_cookies = {}
            self._session_headers = {}
        if cookies:
            self._session_cookies.update(cookies)
        if headers:
            self._session_headers.update(headers)

    def snapshot_session(self):
        return {
            "cookies": dict(self._session_cookies),
            "headers": dict(self._session_headers),
        }

    def restore_session(self, snap):
        self._session_cookies = dict(snap.get("cookies") or {})
        self._session_headers = dict(snap.get("headers") or {})


class ReplaceParamTest(unittest.TestCase):
    def test_replace_existing(self):
        self.assertEqual(_replace_param("https://x/api?user=1&a=2", "user", "1'"),
                         "https://x/api?user=1'&a=2")

    def test_replace_missing_appends(self):
        self.assertEqual(_replace_param("https://x/api?user=1", "id", "5"),
                         "https://x/api?user=1&id=5")

    def test_replace_no_query(self):
        self.assertEqual(_replace_param("https://x/api", "id", "5"),
                         "https://x/api?id=5")


class HasSqlErrorTest(unittest.TestCase):
    def test_mysql_marker(self):
        self.assertTrue(_has_sql_error("You have an error in your SQL syntax near '1'"))

    def test_oracle_marker(self):
        self.assertTrue(_has_sql_error("ORA-00933: SQL command not properly ended"))

    def test_mssql_marker(self):
        self.assertTrue(_has_sql_error("Unclosed quotation mark after the character string"))

    def test_postgres_marker(self):
        self.assertTrue(_has_sql_error('syntax error at or near "1"'))

    def test_no_marker(self):
        self.assertFalse(_has_sql_error("正常页面内容，无报错"))

    def test_markers_nonempty(self):
        self.assertTrue(len(_SQL_ERROR_MARKERS) >= 8)


class SqliProbeTest(unittest.TestCase):
    def test_arg_error_empty_url(self):
        out = sqli_probe(FakeExecutor(), url="", param_name="id")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_arg_error_empty_param(self):
        out = sqli_probe(FakeExecutor(), url="https://x/api?user=1", param_name="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_error_type_hit(self):
        # 前几个响应里出现 SQL 报错特征 → 报错型命中
        ex = FakeExecutor([
            _resp(200, "You have an error in your SQL syntax near '1'"),
            _resp(200, "page"),
        ])
        out = sqli_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["error"])
        self.assertTrue(out["ok"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("报错型" in s for s in out["signals"]))
        # 报错型 4 个 payload 全发
        self.assertEqual(len(out["results"]), 4)

    def test_error_type_negative(self):
        ex = FakeExecutor([_resp(200, "page")] * 4)
        out = sqli_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["error"])
        self.assertEqual(out["verdict"], "negative")
        self.assertEqual(out["signals"], [])

    def test_bool_type_hit(self):
        # 1=1 返回 1000B，1=2 返回 500B → 差异 50% 命中
        ex = FakeExecutor([
            _resp(200, "x" * 1000),
            _resp(200, "x" * 500),
        ])
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id", probe_types=["bool"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("布尔型" in s for s in out["signals"]))
        self.assertEqual(len(out["results"]), 1)

    def test_bool_type_negative(self):
        ex = FakeExecutor([
            _resp(200, "x" * 500),
            _resp(200, "x" * 501),
        ])
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id", probe_types=["bool"])
        self.assertEqual(out["verdict"], "negative")

    def test_time_type_hit(self):
        # sleep 响应耗时通过 mock 无法模拟，这里验证结构 + 不崩
        ex = FakeExecutor([_resp(200, "a"), _resp(200, "b")])
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id", probe_types=["time"])
        self.assertTrue(out["ok"])
        self.assertEqual(len(out["results"]), 1)
        self.assertIn("base_elapsed", out["results"][0])
        self.assertIn("sleep_elapsed", out["results"][0])

    def test_request_cap(self):
        # 全部三类最多 8 个请求
        ex = FakeExecutor([_resp(200, "page")] * 20)
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id")
        self.assertLessEqual(len(ex.calls), 8)

    def test_invalid_probe_type_fallback(self):
        ex = FakeExecutor([_resp(200, "page")] * 20)
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id", probe_types=["weird"])
        self.assertEqual(out["probe_types"], ["error", "bool", "time"])

    def test_guidance_negative(self):
        ex = FakeExecutor([_resp(200, "page")] * 8)
        out = sqli_probe(ex, url="https://x/api?id=1", param_name="id")
        self.assertIn("无明显注入信号", out["guidance"])


class UploadProbeTest(unittest.TestCase):
    def test_arg_error_empty_url(self):
        out = upload_probe(FakeExecutor(), url="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_dangerous_extension_blocked(self):
        for fname in ("shell.php", "a.jsp", "b.asp", "c.aspx", "d.sh", "e.py"):
            out = upload_probe(FakeExecutor(), url="https://x/upload", filename=fname)
            self.assertFalse(out["ok"], f"{fname} 应被拦截")
            self.assertEqual(out["kind"], "arg_error")

    def test_safe_filename_allowed(self):
        ex = FakeExecutor([_resp(200, "ok")])
        out = upload_probe(ex, url="https://x/upload", filename="test.txt")
        self.assertTrue(out["ok"])
        self.assertEqual(out["filename"], "test.txt")

    def test_upload_success_signal(self):
        ex = FakeExecutor([_resp(200, "upload success, file saved")])
        out = upload_probe(ex, url="https://x/upload")
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("返回成功" in s for s in out["signals"]))

    def test_path_hint_signal(self):
        ex = FakeExecutor([_resp(200, 'saved to /uploads/abc.txt')])
        out = upload_probe(ex, url="https://x/upload")
        self.assertTrue(any("上传路径线索" in s for s in out["signals"]))

    def test_size_limit_signal(self):
        ex = FakeExecutor([_resp(400, "file too large, exceeds limit")])
        out = upload_probe(ex, url="https://x/upload")
        self.assertTrue(any("大小限制" in s for s in out["signals"]))

    def test_negative(self):
        ex = FakeExecutor([_resp(404, "not found"), _resp(404, "not found")])
        out = upload_probe(ex, url="https://x/upload")
        self.assertEqual(out["verdict"], "negative")

    def test_max_two_tries(self):
        ex = FakeExecutor([_resp(500, "err"), _resp(500, "err"), _resp(500, "err")])
        upload_probe(ex, url="https://x/upload")
        self.assertLessEqual(len(ex.calls), 2)


class AccessBoundaryTest(unittest.TestCase):
    def test_arg_error_empty_url(self):
        out = access_boundary(FakeExecutor(), url="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_unauthorized_signal(self):
        # 无认证 200 拿到内容 → 未授权信号
        ex = FakeExecutor([_resp(200, "sensitive data"), _resp(200, "sensitive data")])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("未授权访问" in s for s in out["signals"]))

    def test_auth_missing_signal(self):
        # 无认证与登录态响应高度一致 → 鉴权缺失
        ex = FakeExecutor([_resp(200, "x" * 100), _resp(200, "x" * 100)])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertTrue(any("鉴权缺失" in s for s in out["signals"]))

    def test_auth_enforced_signal(self):
        # 无认证 403，登录态 200 → 鉴权生效
        ex = FakeExecutor([_resp(403, "forbidden"), _resp(200, "data")])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertTrue(any("鉴权生效" in s for s in out["signals"]))

    def test_negative(self):
        # 无认证 404，登录态 200 → 无权限边界信号（接口不存在）
        ex = FakeExecutor([_resp(404, "nf"), _resp(200, "data")])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertEqual(out["verdict"], "negative")

    def test_session_restored(self):
        # 无认证请求后会话必须恢复
        ex = FakeExecutor([_resp(200, "a"), _resp(200, "b")])
        access_boundary(ex, url="https://x/api/profile")
        self.assertEqual(ex._session_cookies, {"SID": "abc"})
        self.assertEqual(ex._session_headers, {"X-Token": "t1"})

    def test_anon_and_authed_fields(self):
        ex = FakeExecutor([_resp(200, "a"), _resp(200, "b")])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertEqual(out["anon"]["status"], 200)
        self.assertEqual(out["authed"]["status"], 200)

    def test_session_restored_after_access_boundary(self):
        """access_boundary 测完会话必须恢复原值（深拷贝快照-恢复）。"""
        ex = FakeExecutor([_resp(200, "anon resp"), _resp(200, "authed resp")])
        out = access_boundary(ex, url="https://x/api/profile")
        self.assertTrue(out["ok"])
        self.assertEqual(ex._session_cookies, {"SID": "abc"})
        self.assertEqual(ex._session_headers, {"X-Token": "t1"})

    def test_session_restored_on_exception(self):
        """access_boundary 请求异常时会话也必须恢复。"""
        class ExplodingExecutor(FakeExecutor):
            def http_request(self, *a, **kw):
                raise ConnectionError("boom")
        ex = ExplodingExecutor()
        ex._session_cookies = {"SID": "keep_me"}
        ex._session_headers = {"X-Token": "keep_too"}
        try:
            access_boundary(ex, url="https://x/api/profile")
        except Exception:
            pass
        self.assertEqual(ex._session_cookies, {"SID": "keep_me"})
        self.assertEqual(ex._session_headers, {"X-Token": "keep_too"})


class UploadProbeSideEffectTest(unittest.TestCase):
    """upload_probe 副作用标注：上传成功时返回 side_effects。"""

    def test_side_effects_when_uploaded(self):
        body = '{"status":"upload success","path":"/uploads/test.txt"}'
        ex = FakeExecutor([_resp(200, body)])
        out = upload_probe(ex, url="https://x/upload")
        self.assertTrue(out["ok"])
        self.assertTrue(len(out["side_effects"]) > 0)
        self.assertIn("test.txt", out["side_effects"][0])
        self.assertIn("无法自动删除", out["side_effects"][0])

    def test_no_side_effects_when_not_uploaded(self):
        body = "error: not allowed"
        ex = FakeExecutor([_resp(403, body)])
        out = upload_probe(ex, url="https://x/upload")
        self.assertTrue(out["ok"])
        self.assertEqual(out["side_effects"], [])


if __name__ == "__main__":
    unittest.main()
