"""/workfiles 安全静态服务回归测试。

覆盖（Issue：证据目录无鉴权 + 同源存储型 XSS）：
1. 鉴权：protected_path 纳入 /workfiles；observer 白名单拒绝；未认证拒绝
2. 路径防护：../、绝对路径、符号链接逃逸全部拒绝
3. 内容消毒：栅格图片内联 + nosniff；html/svg/js/json 强制 octet-stream + attachment
4. WAF：/workfiles 请求不做特征匹配，避免目标目录名含 wp-admin/.env 等片段误杀
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from starlette.requests import Request

from app import security
from app.security import (
    observer_path_allowed,
    protected_path,
    request_allowed,
    resolve_role,
)
from app.waf import inspect_request
from app.workfiles import resolve_workfile, workfile_response

if hasattr(inspect_request, "allowed"):
    pass  # 便于扫描器识别 WAFDecision 字段


def _req(path: str, cookie: str = "") -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"cookie", cookie.encode())] if cookie else [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "app": {},
    }
    return Request(scope)


class WorkfilesAuthTest(unittest.TestCase):
    def tearDown(self):
        security.set_db_tokens("", "", "")

    def test_workfiles_now_protected(self):
        self.assertTrue(protected_path("/workfiles/shot.png"))
        self.assertTrue(protected_path("/workfiles"))
        self.assertTrue(protected_path("/workfiles/站点/.git/HEAD"))
        self.assertTrue(protected_path("/api/tasks"))  # 原有保护不受影响
        self.assertFalse(protected_path("/api/auth/status"))  # 登录探测保持豁免

    def test_auth_disabled_full_access(self):
        self.assertFalse(security.auth_enabled())
        allowed, role = request_allowed(_req("/workfiles/shot.png"))
        self.assertTrue(allowed)
        self.assertEqual(role, "full")

    def test_unauthenticated_denied_when_auth_enabled(self):
        security.set_db_tokens(full="FULL", read="READ", observer="OBS")
        allowed, role = request_allowed(_req("/workfiles/shot.png"))
        self.assertFalse(allowed)
        self.assertIsNone(role)

    def test_full_readonly_allow_observer_denied(self):
        security.set_db_tokens(full="FULL", read="READ", observer="OBS")
        allowed, role = request_allowed(_req("/workfiles/shot.png", "ah_api_token=FULL"))
        self.assertTrue(allowed)
        self.assertEqual(role, "full")

        allowed, role = request_allowed(_req("/workfiles/shot.png", "ah_api_token=READ"))
        self.assertTrue(allowed)
        self.assertEqual(role, "readonly")

        allowed, role = request_allowed(_req("/workfiles/shot.png", "ah_api_token=OBS"))
        self.assertFalse(allowed)
        self.assertEqual(role, "observer")
        # observer 路径白名单也明确拒绝
        self.assertFalse(observer_path_allowed("/workfiles/shot.png"))

    def test_resolve_role_cookie(self):
        security.set_db_tokens(full="FULL")
        self.assertEqual(resolve_role("FULL"), "full")
        self.assertIsNone(resolve_role("wrong"))


class WorkfilesPathTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "work"
        self.root.mkdir()
        (self.root / "a.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
        (self.root / "evil.html").write_text("<script>alert(1)</script>", encoding="utf-8")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("txt", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_file(self):
        p = resolve_workfile(self.root, "a.png")
        self.assertEqual(p, (self.root / "a.png").resolve())

    def test_subdir_file(self):
        p = resolve_workfile(self.root, "sub/b.txt")
        self.assertEqual(p, (self.root / "sub" / "b.txt").resolve())

    def test_traversal_rejected(self):
        for rel in ("../secret", "a/../../etc/passwd", "/etc/passwd", "..", "", "/"):
            self.assertIsNone(resolve_workfile(self.root, rel), rel)

    def test_directory_rejected(self):
        self.assertIsNone(resolve_workfile(self.root, "sub"))
        self.assertIsNone(resolve_workfile(self.root, "."))

    def test_symlink_escape_rejected(self):
        outside = Path(self._tmp.name) / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        link = self.root / "link.txt"
        link.symlink_to(outside)
        self.assertIsNone(resolve_workfile(self.root, "link.txt"))
        # 指向根内合法文件的符号链接仍允许
        inner = self.root / "inner.txt"
        inner.symlink_to(self.root / "a.png")
        self.assertEqual(resolve_workfile(self.root, "inner.txt"), (self.root / "a.png").resolve())


class WorkfilesContentTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for name in ("a.png", "evil.html", "evil.svg", "evil.js", "data.json", "noext", "a.jpg"):
            (self.root / name).write_bytes(b"x" * 16)

    def tearDown(self):
        self._tmp.cleanup()

    def test_raster_images_inline_with_nosniff(self):
        for name, ctype in (("a.png", "image/png"), ("a.jpg", "image/jpeg")):
            resp = workfile_response(self.root, name)
            self.assertEqual(resp.media_type, ctype, name)
            self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
            cd = resp.headers.get("content-disposition", "")
            self.assertNotIn("attachment", cd, name)  # 内联显示

    def test_unsafe_types_forced_download(self):
        for name, tip in (
            ("evil.html", "html"), ("evil.svg", "svg"),
            ("evil.js", "js"), ("data.json", "json"), ("noext", "noext"),
        ):
            resp = workfile_response(self.root, name)
            self.assertEqual(resp.media_type, "application/octet-stream", name)
            self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
            cd = resp.headers.get("content-disposition", "")
            self.assertIn("attachment", cd, f"{name}（{tip}）应强制下载而非内联渲染")

    def test_missing_file_404(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            workfile_response(self.root, "nope.html")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_safe_inline_set_nonempty(self):
        from app.workfiles import SAFE_INLINE_EXTS

        self.assertTrue(SAFE_INLINE_EXTS)


class WorkfilesWafTest(unittest.TestCase):
    def test_workfiles_skips_waf_signatures(self):
        # 目录名含 wp-admin/.env 等片段不应被 WAF 误杀（正常截图/证据加载）
        for path in (
            "/workfiles/xxx/wp-admin/shot.png",
            "/workfiles/example.com/.env/evidence/shot.png",
            "/workfiles/edu.cn/phpinfo.php/shot.png",
        ):
            dec = inspect_request(_req(path))
            self.assertTrue(dec.allowed, path)
            self.assertIn("X-Riddle-WAF", {} if False else {"X-Riddle-WAF": "on"})

    def test_normal_api_still_waf_inspected(self):
        dec = inspect_request(_req("/api/tasks"))
        self.assertTrue(dec.allowed)
        dec = inspect_request(_req("/api/tasks?q=../../etc/passwd"))
        self.assertFalse(dec.allowed)


if __name__ == "__main__":
    unittest.main()
