"""阶段三凭证爆破与登录态自动化测试：字典组装/验证码检测/表单识别/登录判定/路径探测。

只测纯逻辑与 mock executor 的确定性行为，不依赖网络。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.auth_tools import (  # noqa: E402
    _build_password_list,
    _has_captcha,
    _identify_form_fields,
    _origin_of,
    credential_brute,
    login_form_scan,
    login_session,
)

LOGIN_HTML = (
    '<html><body><form action="/login" method="post">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<input name="csrf" type="hidden" value="tok123">'
    '<button>登录</button></form></body></html>'
)

CAPTCHA_HTML = (
    '<html><body><form action="/login" method="post">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<input name="captcha" type="text">'
    '<img src="/captcha.png"></form></body></html>'
)


class MockExecutor:
    """模拟 executor：按 URL/method 返回预设响应，记录会话状态。"""

    def __init__(self, responses=None, default_get_body=LOGIN_HTML):
        self.responses = responses or {}
        self.default_get_body = default_get_body
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}
        self.calls: list[dict] = []
        self.cleared = 0

    def http_request(self, url, method="GET", **kwargs):
        self.calls.append({"url": url, "method": method, **kwargs})
        key = (url, method)
        if key in self.responses:
            return self.responses[key]
        # 通配：任何 URL 的 GET 都返回默认页
        if method == "GET":
            return {"ok": True, "status_code": 200, "body": self.default_get_body, "url": url}
        return {"ok": False, "error": "no mock", "status_code": 0}

    def session_set(self, clear=False, **kwargs):
        if clear:
            self._session_cookies = {}
            self._session_headers = {}
            self.cleared += 1
        else:
            self._session_cookies.update(kwargs.get("cookies") or {})
            self._session_headers.update(kwargs.get("headers") or {})

    def snapshot_session(self):
        return {
            "cookies": dict(self._session_cookies),
            "headers": dict(self._session_headers),
        }

    def restore_session(self, snap):
        self._session_cookies = dict(snap.get("cookies") or {})
        self._session_headers = dict(snap.get("headers") or {})


def _login_ok_response(url):
    return {
        "ok": True, "status_code": 302, "url": url,
        "final_url": "http://example.edu.cn/home",
        "body": "",
        "set_cookie": "JSESSIONID=abc123",
    }


def _login_fail_response(url):
    return {
        "ok": True, "status_code": 200, "url": url,
        "final_url": url, "body": "用户名或密码错误",
    }


class BuildPasswordListTest(unittest.TestCase):
    def test_user_specified_first(self):
        out = _build_password_list("admin", ["MyPass1"], use_builtin=False, edu_mode=False)
        self.assertEqual(out[0], "MyPass1")
        # 用户名变体始终追加（不依赖内置字典）
        self.assertIn("admin", out)
        self.assertIn("admin123", out)

    def test_builtin_generic(self):
        out = _build_password_list("admin", None, use_builtin=True, edu_mode=False)
        self.assertIn("admin123", out)
        self.assertIn("123456", out)
        self.assertIn("admin@123", out)

    def test_edu_mode_uses_edu_dict(self):
        # 用户名用 stu，避免变体与字典词重叠干扰判断
        out = _build_password_list("stu", None, use_builtin=True, edu_mode=True)
        self.assertIn("Aa123456", out)  # 教育字典词
        self.assertNotIn("admin@123", out)  # 通用专有口令不在教育字典，也不是 stu 的变体
        self.assertNotIn("admin888", out)

    def test_username_variants_appended(self):
        out = _build_password_list("stu2023", None, use_builtin=False, edu_mode=False)
        self.assertIn("stu2023", out)
        self.assertIn("stu2023123", out)
        self.assertIn("stu2023@123", out)

    def test_dedup_keeps_order(self):
        out = _build_password_list("admin", ["123456", "123456"], use_builtin=True, edu_mode=False)
        self.assertEqual(out.count("123456"), 1)

    def test_empty_passwords_no_builtin(self):
        out = _build_password_list("", None, use_builtin=False, edu_mode=False)
        self.assertEqual(out, [])


class HasCaptchaTest(unittest.TestCase):
    def test_captcha_marker_in_body(self):
        has, ev = _has_captcha("请输入验证码", {})
        self.assertTrue(has)
        self.assertIn("验证码", ev)

    def test_captcha_field_in_form(self):
        has, _ = _has_captcha("", {"captcha": ""})
        self.assertTrue(has)

    def test_no_captcha(self):
        has, ev = _has_captcha("普通登录页", {"username": "", "password": ""})
        self.assertFalse(has)
        self.assertEqual(ev, "")

    def test_locked_marker(self):
        has, _ = _has_captcha("尝试次数过多，账号已锁定", {})
        self.assertTrue(has)


class IdentifyFormFieldsTest(unittest.TestCase):
    def test_standard_fields(self):
        ident = _identify_form_fields({"username": "", "password": "", "csrf": "x"})
        self.assertIn("username", ident["user"])
        self.assertIn("password", ident["pass"])
        self.assertEqual(ident["captcha"], [])

    def test_captcha_field(self):
        ident = _identify_form_fields({"account": "", "pwd": "", "verifyCode": ""})
        self.assertIn("account", ident["user"])
        self.assertIn("pwd", ident["pass"])
        self.assertIn("verifyCode", ident["captcha"])


class OriginOfTest(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(_origin_of("https://jwxt.example.edu.cn:8443/login"), "https://jwxt.example.edu.cn:8443")

    def test_bare_domain(self):
        self.assertEqual(_origin_of("example.edu.cn"), "http://example.edu.cn")


class CredentialBruteTest(unittest.TestCase):
    def test_success_keeps_session(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
            ("http://example.edu.cn/login", "POST"): _login_ok_response("http://example.edu.cn/login"),
        })
        res = credential_brute(ex, login_url="http://example.edu.cn/login", username="admin",
                               passwords=["admin123"], use_builtin_dict=False, delay=0)
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["found"]), 1)
        self.assertEqual(res["found"][0]["username"], "admin")
        self.assertEqual(res["found"][0]["password"], "admin123")
        self.assertTrue(res["session_kept"])
        # 命中即停：只尝试了 1 次
        posts = [c for c in ex.calls if c["method"] == "POST"]
        self.assertEqual(len(posts), 1)

    def test_captcha_stops_immediately(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": CAPTCHA_HTML, "url": "http://example.edu.cn/login",
            },
        })
        res = credential_brute(ex, login_url="http://example.edu.cn/login", username="admin", delay=0)
        self.assertFalse(res["ok"])
        self.assertTrue(res.get("stopped"))
        self.assertIn("验证码", res.get("error", ""))
        posts = [c for c in ex.calls if c["method"] == "POST"]
        self.assertEqual(len(posts), 0)

    def test_no_match_returns_empty(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
            ("http://example.edu.cn/login", "POST"): _login_fail_response("http://example.edu.cn/login"),
        })
        res = credential_brute(ex, login_url="http://example.edu.cn/login", username="admin",
                               passwords=["wrong1"], use_builtin_dict=False, delay=0)
        self.assertTrue(res["ok"])
        self.assertEqual(res["found"], [])
        self.assertIn("未命中", res["guidance"])

    def test_missing_args(self):
        res = credential_brute(MockExecutor(), login_url="", username="")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "arg_error")

    def test_max_attempts_capped(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
            ("http://example.edu.cn/login", "POST"): _login_fail_response("http://example.edu.cn/login"),
        })
        res = credential_brute(ex, login_url="http://example.edu.cn/login", username="admin",
                               passwords=["a", "b", "c"], use_builtin_dict=False, max_attempts=2, delay=0)
        self.assertTrue(res["ok"])
        self.assertEqual(res["attempts"], 2)
        posts = [c for c in ex.calls if c["method"] == "POST"]
        self.assertEqual(len(posts), 2)


class LoginSessionTest(unittest.TestCase):
    def test_login_ok(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
            ("http://example.edu.cn/login", "POST"): _login_ok_response("http://example.edu.cn/login"),
        })
        ex._session_cookies = {"JSESSIONID": "abc123"}
        res = login_session(ex, login_url="http://example.edu.cn/login", username="admin", password="admin123")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "login_ok")
        self.assertIn("JSESSIONID", res["session_cookies"])

    def test_login_fail(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
            ("http://example.edu.cn/login", "POST"): _login_fail_response("http://example.edu.cn/login"),
        })
        res = login_session(ex, login_url="http://example.edu.cn/login", username="admin", password="bad")
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "login_fail")

    def test_missing_args(self):
        res = login_session(MockExecutor(), login_url="", username="", password="")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "arg_error")


class LoginFormScanTest(unittest.TestCase):
    def test_finds_login_form(self):
        ex = MockExecutor({
            ("http://example.edu.cn/login", "GET"): {
                "ok": True, "status_code": 200, "body": LOGIN_HTML, "url": "http://example.edu.cn/login",
            },
        })
        res = login_form_scan(ex, url="http://example.edu.cn", max_paths=2)
        self.assertTrue(res["ok"])
        self.assertTrue(res["found"])
        first = res["found"][0]
        self.assertIn("username", first["fields"])
        self.assertIn("password", first["fields"])
        self.assertFalse(first["has_captcha"])

    def test_detects_captcha(self):
        ex = MockExecutor(
            responses={
                ("http://example.edu.cn/login", "GET"): {
                    "ok": True, "status_code": 200, "body": CAPTCHA_HTML, "url": "http://example.edu.cn/login",
                },
            },
            default_get_body=CAPTCHA_HTML,
        )
        res = login_form_scan(ex, url="http://example.edu.cn", max_paths=2)
        self.assertTrue(res["ok"])
        self.assertTrue(res["found"])
        self.assertTrue(any(p["has_captcha"] for p in res["found"]))

    def test_no_login_found(self):
        ex = MockExecutor(
            responses={
                ("http://example.edu.cn/login", "GET"): {
                    "ok": True, "status_code": 200, "body": "<html>普通首页</html>", "url": "http://example.edu.cn/login",
                },
            },
            default_get_body="<html>普通首页</html>",
        )
        res = login_form_scan(ex, url="http://example.edu.cn", max_paths=1)
        self.assertTrue(res["ok"])
        self.assertEqual(res["found"], [])

    def test_missing_args(self):
        res = login_form_scan(MockExecutor(), url="")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "arg_error")


class SessionRestoreTest(unittest.TestCase):
    """闭环恢复：credential_brute / login_session 失败后必须恢复原会话。"""

    def test_credential_brute_fail_restores_session(self):
        """爆破全部失败后，原会话 cookie/header 必须恢复。"""
        ex = MockExecutor()
        ex._session_cookies = {"SID": "original_session", "TOKEN": "abc"}
        ex._session_headers = {"X-Auth": "bearer xyz"}
        # 登录页 GET 返回正常表单，POST 全部返回失败
        ex.responses = {}
        ex.default_get_body = LOGIN_HTML
        ex.responses = {
            ("http://example.edu.cn/login", "POST"): _login_fail_response("http://example.edu.cn/login"),
        }
        # credential_brute 内部每次 _try_login_once 会 session_set(clear=True)
        res = credential_brute(ex, login_url="http://example.edu.cn/login",
                                username="admin", passwords=["wrong1", "wrong2"],
                                use_builtin_dict=False, max_attempts=2)
        self.assertFalse(res["found"])
        self.assertTrue(res.get("session_restored"))
        # 原会话必须恢复
        self.assertEqual(ex._session_cookies.get("SID"), "original_session")
        self.assertEqual(ex._session_cookies.get("TOKEN"), "abc")
        self.assertEqual(ex._session_headers.get("X-Auth"), "bearer xyz")

    def test_credential_brute_hit_keeps_new_session(self):
        """爆破命中后保持新会话，不恢复原会话。"""
        ex = MockExecutor()
        ex._session_cookies = {"OLD": "old_session"}
        ex.default_get_body = LOGIN_HTML
        ex.responses = {
            ("http://example.edu.cn/login", "POST"): _login_ok_response("http://example.edu.cn/login"),
        }
        res = credential_brute(ex, login_url="http://example.edu.cn/login",
                                username="admin", passwords=["admin123"],
                                use_builtin_dict=False, max_attempts=1)
        self.assertTrue(res["found"])
        self.assertTrue(res.get("session_kept"))
        self.assertNotIn("OLD", ex._session_cookies)

    def test_login_session_fail_restores_session(self):
        """login_session 登录失败后恢复原会话。"""
        ex = MockExecutor()
        ex._session_cookies = {"SID": "original"}
        ex.default_get_body = LOGIN_HTML
        ex.responses = {
            ("http://example.edu.cn/login", "POST"): _login_fail_response("http://example.edu.cn/login"),
        }
        res = login_session(ex, login_url="http://example.edu.cn/login",
                            username="admin", password="wrong")
        self.assertFalse(res["ok"])
        self.assertTrue(res.get("session_restored"))
        self.assertEqual(ex._session_cookies.get("SID"), "original")

    def test_login_session_hit_keeps_new_session(self):
        """login_session 登录成功后保持新会话。"""
        ex = MockExecutor()
        ex._session_cookies = {"OLD": "old"}
        ex.default_get_body = LOGIN_HTML
        ex.responses = {
            ("http://example.edu.cn/login", "POST"): _login_ok_response("http://example.edu.cn/login"),
        }
        res = login_session(ex, login_url="http://example.edu.cn/login",
                            username="admin", password="admin123")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "login_ok")


if __name__ == "__main__":
    unittest.main()
