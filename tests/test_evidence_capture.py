"""自动存证快照测试：文本提取 / 快照抓取 / 持久化 / 工具 / worker 自动存证。"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.evidence_capture import (  # noqa: E402
    _extract_meta,
    _extract_title,
    _extract_visible_text,
    _pick_headers,
    capture_evidence,
    capture_snapshot,
    load_snapshot,
    render_snapshot_markdown,
    save_snapshot,
    snapshot_to_text,
)
from app.agents import worker as worker_mod  # noqa: E402
from app.schemas import Finding  # noqa: E402

_HTML = (
    "<html><head><title>  教务系统 - 登录  </title>"
    '<meta name="description" content="  学校教务管理平台  "></head>'
    "<body><script>var x=1;</script><style>.a{}</style>"
    "<h1>欢迎登录</h1><p>请输入账号密码</p><!-- comment --></body></html>"
)


def _resp(status=200, body="", headers=None, body_len=None, url="https://x/"):
    return {
        "ok": True, "status_code": status, "body": body,
        "body_len": len(body) if body_len is None else body_len,
        "response_headers": headers or {},
        "url": url,
    }


class FakeExecutor:
    def __init__(self, responses=None, work_dir=None):
        self.responses = list(responses or [])
        self.calls = []
        self._session_cookies = {"SID": "abc"}
        self._session_headers = {}
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp())

    def http_request(self, url, method="GET", headers=None, data=None, timeout=20, **kw):
        self.calls.append({"url": url, "method": method, "data": data})
        if self.responses:
            resp = dict(self.responses.pop(0))
            resp["url"] = url
            return resp
        return _resp(url=url)


class ExtractTest(unittest.TestCase):
    def test_title(self):
        self.assertEqual(_extract_title(_HTML), "教务系统 - 登录")

    def test_title_missing(self):
        self.assertEqual(_extract_title("<html><body>no title</body></html>"), "")

    def test_meta(self):
        self.assertEqual(_extract_meta(_HTML), "学校教务管理平台")

    def test_meta_reversed_attrs(self):
        self.assertEqual(
            _extract_meta('<meta content="desc-x" name="description">'), "desc-x")

    def test_visible_text(self):
        text = _extract_visible_text(_HTML)
        self.assertIn("欢迎登录", text)
        self.assertIn("请输入账号密码", text)
        self.assertNotIn("var x", text)
        self.assertNotIn("comment", text)

    def test_visible_text_limit(self):
        text = _extract_visible_text("<p>abcdefghij</p>", max_len=5)
        self.assertEqual(text, "abcde")

    def test_pick_headers(self):
        hdrs = _pick_headers({
            "Content-Type": "text/html", "Server": "nginx",
            "X-Powered-By": "PHP/7.4", "Set-Cookie": "SID=1",
            "X-Random": "noise", "Date": "today",
        })
        self.assertIn("Content-Type", hdrs)
        self.assertIn("Server", hdrs)
        self.assertIn("X-Powered-By", hdrs)
        self.assertIn("Set-Cookie", hdrs)
        self.assertNotIn("X-Random", hdrs)
        self.assertNotIn("Date", hdrs)


class CaptureSnapshotTest(unittest.TestCase):
    def test_success(self):
        ex = FakeExecutor([_resp(200, _HTML, {"Content-Type": "text/html", "Server": "nginx"})])
        snap = capture_snapshot(ex, "https://x/login")
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["status"], 200)
        self.assertEqual(snap["title"], "教务系统 - 登录")
        self.assertEqual(snap["meta_description"], "学校教务管理平台")
        self.assertIn("欢迎登录", snap["visible_text"])
        self.assertIn("text/html", snap["headers"].get("Content-Type", ""))
        self.assertIn("nginx", snap["headers"].get("Server", ""))
        self.assertGreaterEqual(snap["body_len"], len(_HTML))
        self.assertIn("body_snippet", snap)
        self.assertIn("captured_at", snap)

    def test_arg_error(self):
        ex = FakeExecutor()
        snap = capture_snapshot(ex, "")
        self.assertFalse(snap["ok"])
        self.assertEqual(snap["kind"], "arg_error")

    def test_http_failure(self):
        ex = FakeExecutor([{"ok": False, "error": "连接被拒", "url": "https://x/"}])
        snap = capture_snapshot(ex, "https://x/")
        self.assertFalse(snap["ok"])
        self.assertIn("连接被拒", snap["error"])

    def test_exception_safe(self):
        class Boom:
            def http_request(self, *a, **k):
                raise RuntimeError("boom")
        snap = capture_snapshot(Boom(), "https://x/")
        self.assertFalse(snap["ok"])
        self.assertIn("boom", snap["error"])


class SnapshotTextTest(unittest.TestCase):
    def test_to_text(self):
        ex = FakeExecutor([_resp(200, _HTML)])
        snap = capture_snapshot(ex, "https://x/login")
        text = snapshot_to_text(snap)
        self.assertIn("存证快照", text)
        self.assertIn("教务系统", text)
        self.assertIn("200", text)

    def test_to_text_failed(self):
        self.assertIn("失败", snapshot_to_text({"ok": False}))


class PersistTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            ex = FakeExecutor([_resp(200, _HTML)])
            snap = capture_snapshot(ex, "https://x/login")
            ref = save_snapshot(td, snap)
            self.assertTrue(ref.startswith("evidence/snap_"))
            loaded = load_snapshot(td, ref)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["status"], 200)
            self.assertEqual(loaded["title"], "教务系统 - 登录")
            # body_snippet 从 .html 回填
            self.assertIn("欢迎登录", loaded["body_snippet"])
            # JSON 落盘内容不带 body_snippet（单独落 .html）
            saved_json = (Path(td) / ref).read_text(encoding="utf-8")
            self.assertNotIn("body_snippet", saved_json)

    def test_load_missing(self):
        self.assertIsNone(load_snapshot("nope", "evidence/x.json"))

    def test_load_empty_ref(self):
        self.assertIsNone(load_snapshot("nope", ""))

    def test_save_failed_snapshot(self):
        self.assertEqual(save_snapshot("nope", {"ok": False}), "")


class RenderMarkdownTest(unittest.TestCase):
    def test_render(self):
        ex = FakeExecutor([_resp(200, _HTML)])
        snap = capture_snapshot(ex, "https://x/login")
        md = render_snapshot_markdown(snap)
        self.assertIn("https://x/login", md)
        self.assertIn("200", md)
        self.assertIn("教务系统", md)
        self.assertIn("原始 HTML 片段", md)

    def test_render_failed(self):
        self.assertIn("失败", render_snapshot_markdown({"ok": False}))


class CaptureEvidenceToolTest(unittest.TestCase):
    def test_arg_error(self):
        ex = FakeExecutor()
        out = capture_evidence(ex, url="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_success_with_ref(self):
        with tempfile.TemporaryDirectory() as td:
            ex = FakeExecutor([_resp(200, _HTML)], work_dir=td)
            out = capture_evidence(ex, url="https://x/login")
            self.assertTrue(out["ok"])
            self.assertEqual(out["status"], 200)
            self.assertTrue(out["evidence_ref"].startswith("evidence/snap_"))
            self.assertIn("存证快照已保存", out["summary"])
            self.assertIn("snapshot_ref", out["guidance"])
            # 持久化文件确实落盘
            self.assertTrue((Path(td) / out["evidence_ref"]).exists())

    def test_http_failure(self):
        ex = FakeExecutor([{"ok": False, "error": "超时", "url": "https://x/"}])
        out = capture_evidence(ex, url="https://x/")
        self.assertFalse(out["ok"])
        self.assertIn("超时", out["error"])


class AutoCaptureEvidenceTest(unittest.TestCase):
    def _finding(self, **ev):
        return Finding(
            vuln_type="idor", title="越权", severity_claimed="中危",
            target_url="https://x/api/profile", owner="测试大学",
            description="d", steps=["1"], poc="curl x",
            evidence=ev,
        )

    def _worker(self, ex):
        w = worker_mod.Worker.__new__(worker_mod.Worker)
        w.executor = ex
        w.findings = []
        w._emit = lambda *a, **k: None
        return w

    def test_auto_capture_on_submit(self):
        with tempfile.TemporaryDirectory() as td:
            ex = FakeExecutor([_resp(200, _HTML)], work_dir=td)
            w = self._worker(ex)
            f = self._finding()
            w._auto_capture_evidence(f)
            self.assertIsNotNone(f.evidence.snapshot)
            self.assertEqual(f.evidence.snapshot["status"], 200)
            self.assertTrue(f.evidence.snapshot_ref.startswith("evidence/snap_"))

    def test_resolve_snapshot_ref(self):
        with tempfile.TemporaryDirectory() as td:
            ex = FakeExecutor([_resp(200, _HTML)], work_dir=td)
            w = self._worker(ex)
            # 先手动存一份快照拿 ref
            out = capture_evidence(ex, url="https://x/poc?id=1")
            ref = out["evidence_ref"]
            # 提交时带 snapshot_ref → 直接合并，不再发请求
            ex.calls.clear()
            f = self._finding(snapshot_ref=ref)
            w._auto_capture_evidence(f)
            self.assertIsNotNone(f.evidence.snapshot)
            self.assertEqual(f.evidence.snapshot["url"], "https://x/poc?id=1")
            self.assertEqual(ex.calls, [])  # 未再发请求

    def test_failure_does_not_block(self):
        class Boom:
            work_dir = Path(tempfile.mkdtemp())
            def http_request(self, *a, **k):
                raise RuntimeError("boom")
        w = self._worker(Boom())
        f = self._finding()
        w._auto_capture_evidence(f)  # 不应抛异常
        self.assertIsNone(f.evidence.snapshot)


if __name__ == "__main__":
    unittest.main()
