"""worker 智能化：攻击面/参数可控性探测工具 + 结构化认知卡（纯规则）测试。

覆盖：http_batch 批量遍历、diff_response 差异对比、timing_probe 测时、crawl_links 抓取，
以及 executor 的 update_cognition / session_status_block 结构化记忆渲染。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.attack_tools import crawl_links, diff_response, http_batch, timing_probe  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402


def _resp(status=200, body="", url="", headers=None):
    return {
        "ok": True, "status_code": status, "url": url,
        "body": body, "body_len": len(body),
        "response_headers": headers or {},
    }


class MockExecutor:
    def __init__(self, matcher=None):
        self.matcher = matcher or (lambda url, method, **kw: _resp(200, "<html></html>", url))
        self.calls = []

    def http_request(self, url, method="GET", **kwargs):
        self.calls.append((url, method))
        r = self.matcher(url, method, **kwargs)
        r["url"] = r.get("url") or url
        return r


class HttpBatchTest(unittest.TestCase):
    def test_placeholder_iteration_and_diff(self):
        def matcher(url, method, **kw):
            if "/user/2" in url:
                return _resp(404, "not found", url)
            if "/user/3" in url:
                return _resp(200, "姓名 张三 手机 13800138000", url)
            return _resp(200, "ok", url)
        ex = MockExecutor(matcher)
        res = http_batch(ex, url="https://x/api/user/{p}", start=1, end=4,
                         delay=0, interest_contains=["手机"])
        self.assertTrue(res["ok"])
        # 4 个值都被扫描
        self.assertEqual({c[0] for c in ex.calls}, {
            "https://x/api/user/1", "https://x/api/user/2",
            "https://x/api/user/3", "https://x/api/user/4",
        })
        self.assertIn(404, res["status_counts"])
        # 与基线(1)比，2(status变)、3(带手机号且明显长) 应进 diff
        self.assertTrue(len(res["diff_samples"]) >= 2)
        # 命中兴趣关键词
        self.assertTrue(any(s["i"] == 3 for s in res["interesting_samples"]))

    def test_param_name_replaces_url(self):
        def matcher(url, method, **kw):
            return _resp(200, "ok", url)
        ex = MockExecutor(matcher)
        res = http_batch(ex, url="https://x/api?id=1", param_name="id", start=5, end=5, delay=0)
        self.assertTrue(res["ok"])
        self.assertEqual(ex.calls[0][0], "https://x/api?id=5")

    def test_missing_placeholder(self):
        ex = MockExecutor()
        res = http_batch(ex, url="https://x/api")
        self.assertFalse(res["ok"])
        self.assertEqual(res.get("kind"), "arg_error")

    def test_missing_url(self):
        ex = MockExecutor()
        res = http_batch(ex, url="")
        self.assertFalse(res["ok"])


class DiffResponseTest(unittest.TestCase):
    def test_sig_change(self):
        def matcher(url, method, **kw):
            if "id=999" in url:
                return _resp(200, "权限不足", url)
            return _resp(200, "用户详情 name=alice id=1", url)
        ex = MockExecutor(matcher)
        res = diff_response(ex, url="https://x/user", params_a={"id": "1"}, params_b={"id": "999"})
        self.assertTrue(res["ok"])
        self.assertTrue(res["diff"]["sig_attr"])

    def test_no_change(self):
        def matcher(url, method, **kw):
            return _resp(200, "same", url)
        ex = MockExecutor(matcher)
        res = diff_response(ex, url="https://x/user", params_a={"id": "1"}, params_b={"id": "999"})
        self.assertTrue(res["ok"])
        self.assertFalse(res["diff"]["sig_attr"])

    def test_missing_url(self):
        res = diff_response(MockExecutor(), url="")
        self.assertFalse(res["ok"])


class TimingProbeTest(unittest.TestCase):
    def test_basic_stats(self):
        ex = MockExecutor(lambda url, method, **kw: _resp(200, "ok", url))
        res = timing_probe(ex, url="https://x/sleep?x=1", samples=3)
        self.assertTrue(res["ok"])
        self.assertEqual(res["samples"], 3)
        self.assertEqual(res["status"], 200)
        for k in ("min_ms", "p50_ms", "max_ms", "avg_ms"):
            self.assertIn(k, res)

    def test_missing_url(self):
        res = timing_probe(MockExecutor(), url="")
        self.assertFalse(res["ok"])

    def test_sample_clamped(self):
        ex = MockExecutor(lambda url, method, **kw: _resp(200, "ok", url))
        res = timing_probe(ex, url="https://x/t", samples=100)
        self.assertLessEqual(res["samples"], 7)


class CrawlLinksTest(unittest.TestCase):
    HTML = ('<html><a href="/">首页</a><a href="/api/user">用户接口</a>'
            '<a href="https://else.example.com/other">外站</a>'
            '<form action="/submit"><input></form>'
            '<script src="/app.js"></script></html>')

    def test_extracts_internal_and_api(self):
        def matcher(url, method, **kw):
            if url == "https://x.example.com/":
                return _resp(200, self.HTML, url, {"content-type": "text/html"})
            return _resp(200, "<html></html>", url, {"content-type": "text/html"})
        ex = MockExecutor(matcher)
        res = crawl_links(ex, url="https://x.example.com/", max_pages=2, timeout=5)
        self.assertTrue(res["ok"])
        urls = " ".join(res["links"])
        self.assertIn("/api/user", urls)
        self.assertIn("/submit", urls)
        # 外站被同主机过滤
        self.assertNotIn("else.example.com", urls)
        self.assertTrue(any("api" in u for u in res["api_like"]))

    def test_missing_url(self):
        res = crawl_links(MockExecutor(), url="")
        self.assertFalse(res["ok"])


class ExecutorCognitionTest(unittest.TestCase):
    def setUp(self):
        self.ex = ToolExecutor(target="https://x.example.com", work_dir=str(ROOT / "_tmp_cog"))

    def test_update_and_render(self):
        self.ex.update_cognition(slot="confirmed", text="能读他人成绩单")
        self.ex.update_cognition(slot="confirmed", text="能读他人成绩单")  # 去重
        self.ex.update_cognition(slot="excluded", text="弱口令已排除")
        self.ex.update_cognition(slot="leads", text="token 疑似可重放")
        self.ex.update_cognition(slot="plan", text="下一步验证 /api/admin/users 越权")
        block = self.ex.session_status_block()
        self.assertIn("已证实", block)
        self.assertIn("能读他人成绩单", block)
        self.assertIn("已排除", block)
        self.assertIn("活跃线索", block)
        self.assertIn("当前计划", block)

    def test_invalid_slot(self):
        r = self.ex.update_cognition(slot="bad", text="x")
        self.assertFalse(r["ok"])
        self.assertEqual(r.get("kind"), "arg_error")

    def test_empty_text(self):
        r = self.ex.update_cognition(slot="confirmed", text="")
        self.assertFalse(r["ok"])

    def test_cap_and_restore(self):
        for i in range(20):
            self.ex.update_cognition(slot="leads", text=f"l{i}")
        self.assertLessEqual(len(self.ex._cognition["leads"]), 10)
        snap = self.ex.export_resume_state()
        ex2 = ToolExecutor(target="https://x.example.com", work_dir=str(ROOT / "_tmp_cog2"))
        ex2.restore_resume_state(cognition=snap["cognition"])
        self.assertEqual(ex2._cognition["leads"], self.ex._cognition["leads"])


if __name__ == "__main__":
    unittest.main()