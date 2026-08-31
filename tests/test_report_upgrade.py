import io
import sys
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api import findings  # noqa: E402
from app.report_export import (  # noqa: E402
    build_docx_bytes, build_report_html, build_report_markdown, build_report_sections,
    score_breakdown,
)


def _finding(**over):
    base = dict(
        id="f" * 32, task_id="t" * 32, target_id="g" * 32, vuln_type="sql_injection",
        title="登录接口 SQL 注入", severity_claimed="高危", target_url="https://example.edu.cn/login",
        owner="示例大学", description="登录接口存在 SQL 注入。", steps=["注入万能口令", "绕过认证"],
        poc="curl -s 'https://example.edu.cn/api/login' -d 'username=admin'",
        raw_request="POST /api/login HTTP/1.1\nHost: example.edu.cn\n\nusername=admin",
        raw_response="HTTP/1.1 302 Found\nLocation: /admin/dashboard\n\n",
        evidence={"extracted_data_sample": "id=2 返回：{\"id\":2,\"name\":\"张三\"}"},
        affected_scope="可读取全站用户账号信息。",
        kill_chain=[{"method": "前端 JS 审计", "detail": "提取到 /api/login"}],
        assistant_messages=[], self_check={}, llm_model="deepseek-chat", llm_base_url="",
        status="reviewed", created_at=None, edu_school="示例大学",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _review(**over):
    base = dict(
        id="r" * 32, finding_id="f" * 32, task_id="t" * 32, verdict="accepted",
        confidence="confirmed", severity_final="高危", score=8.5, in_scope=True,
        is_duplicate=False, ignore_reasons=[], downgrade_reasons=[], reproduced=True,
        reviewer_notes="证据链完整，等级成立。", deepen_directive="", reviewed_at=None,
        user_status="passed", user_severity="高危", user_notes="已人工复核。",
        user_edits={}, submitted=False, user_reviewed_at=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


class ScoreBreakdownTest(unittest.TestCase):
    def test_high_severity_reproduced_scores_high(self):
        f = _finding()
        r = _review()
        sb = score_breakdown(f, r)
        self.assertIsNotNone(sb)
        self.assertGreaterEqual(sb["impact"], 8.0)
        self.assertGreaterEqual(sb["exploitability"], 7.0)
        self.assertGreaterEqual(sb["reproducibility"], 7.0)
        self.assertAlmostEqual(sb["total"], round((sb["impact"] + sb["exploitability"] + sb["scope"] + sb["reproducibility"]) / 4, 1))

    def test_no_review_returns_none(self):
        self.assertIsNone(score_breakdown(_finding(), None))

    def test_low_severity_no_evidence_scores_low(self):
        f = _finding(severity_claimed="低危", poc="", raw_request="", raw_response="", steps=[], evidence={})
        r = _review(severity_final="低危", user_severity="低危", reproduced=False, in_scope=False, affected_scope="")
        sb = score_breakdown(f, r)
        self.assertLessEqual(sb["impact"], 3.0)
        self.assertLessEqual(sb["exploitability"], 5.0)


class ReportSectionsTemplateTest(unittest.TestCase):
    def test_edusrc_template_sections(self):
        f = _finding()
        r = _review()
        sec = build_report_sections(f, r, "edusrc")
        keys = [s["key"] for s in sec["template"]["sections"]]
        self.assertIn("overview", keys)
        self.assertIn("evidence", keys)
        self.assertIn("chain", keys)
        self.assertEqual(sec["data"]["overview"]["title"], "登录接口 SQL 注入")
        self.assertEqual(sec["data"]["steps"], [
            {"desc": "注入万能口令", "poc": "", "poc_http": ""},
            {"desc": "绕过认证", "poc": "", "poc_http": ""},
        ])
        self.assertEqual(len(sec["data"]["chain"]), 1)

    def test_object_steps_keep_per_step_poc(self):
        f = _finding(steps=[
            {"desc": "访问登录接口", "poc": "curl -s 'https://example.edu.cn/api/login'"},
            {"desc": "注入万能口令", "poc": "curl -s 'https://example.edu.cn/api/login' -d 'username=admin'"},
            "纯说明步骤",
        ])
        r = _review()
        sec = build_report_sections(f, r, "edusrc")
        self.assertEqual(sec["data"]["steps"][0], {
            "desc": "访问登录接口", "poc": "curl -s 'https://example.edu.cn/api/login'", "poc_http": "",
        })
        self.assertEqual(sec["data"]["steps"][1]["poc"], "curl -s 'https://example.edu.cn/api/login' -d 'username=admin'")
        self.assertEqual(sec["data"]["steps"][2], {"desc": "纯说明步骤", "poc": "", "poc_http": ""})
        self.assertEqual(sec["data"]["overview"]["steps_count"], 3)
        md = build_report_markdown(f, r, "edusrc")
        self.assertIn("1. **访问登录接口**", md)
        self.assertIn("curl -s 'https://example.edu.cn/api/login' -d 'username=admin'", md)

    def test_object_steps_export_docx_and_html(self):
        f = _finding(steps=[
            {"desc": "访问登录接口", "poc": "curl -s 'https://example.edu.cn/api/login'"},
            "纯说明步骤",
        ])
        r = _review()
        doc = build_docx_bytes(f, r, "edusrc")
        zf = zipfile.ZipFile(io.BytesIO(doc))
        xml = zf.read("word/document.xml").decode("utf-8")
        self.assertIn("1. 访问登录接口", xml)
        self.assertIn("curl -s 'https://example.edu.cn/api/login'", xml)
        self.assertIn("2. 纯说明步骤", xml)
        html = build_report_html(f, r, "edusrc")
        self.assertIn("<li>访问登录接口<pre>curl -s &#x27;https://example.edu.cn/api/login&#x27;</pre></li>", html)
        self.assertIn("<li>纯说明步骤</li>", html)

    def test_overview_embeds_score_breakdown(self):
        f = _finding()
        r = _review()
        sec = build_report_sections(f, r, "edusrc")
        sb = sec["data"]["overview"]["score_breakdown"]
        self.assertIsNotNone(sb)
        for key in ("impact", "exploitability", "scope", "reproducibility", "total"):
            self.assertIn(key, sb)

    def test_enterprise_template_uses_business_impact_label(self):
        f = _finding()
        r = _review()
        sec = build_report_sections(f, r, "enterprise")
        labels = {s["key"]: s["label"] for s in sec["template"]["sections"]}
        self.assertEqual(labels["scope"], "业务影响")

    def test_unknown_template_falls_back_to_edusrc(self):
        f = _finding()
        r = _review()
        sec = build_report_sections(f, r, "whatever")
        self.assertEqual(sec["template"]["label"], "教育行业")

    def test_user_edits_override_originals(self):
        f = _finding(description="原始描述")
        r = _review(user_edits={"description": "用户改后的描述"})
        sec = build_report_sections(f, r, "edusrc")
        self.assertEqual(sec["data"]["description"], "用户改后的描述")

    def test_owner_falls_back_when_no_edu_school_attr(self):
        """模型无 edu_school 列（API 层派生字段），未补时兜底 owner，不应抛 AttributeError。"""
        from app.report_export import _owner
        f = _finding()
        delattr(f, "edu_school") if hasattr(f, "edu_school") else None
        self.assertEqual(_owner(f), "示例大学")


class ReportMarkdownTest(unittest.TestCase):
    def test_markdown_contains_all_sections(self):
        f = _finding()
        r = _review()
        md = build_report_markdown(f, r, "edusrc")
        for needle in ("# 登录接口 SQL 注入", "## 漏洞描述", "## 影响范围", "## 复现步骤", "## 验证 PoC", "## 证据链", "## 攻击链路", "## AI 审核结论", "## 风险评分分解"):
            self.assertIn(needle, md)


class ReportDocxTest(unittest.TestCase):
    def test_docx_is_valid_zip_with_document_xml(self):
        f = _finding()
        r = _review()
        data = build_docx_bytes(f, r, "edusrc")
        self.assertGreater(len(data), 1000)
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        self.assertIn("[Content_Types].xml", names)
        self.assertIn("word/document.xml", names)
        doc = zf.read("word/document.xml").decode("utf-8")
        self.assertIn("登录接口 SQL 注入", doc)
        self.assertIn("注入万能口令", doc)
        self.assertIn("风险评分分解", doc)


class ReportHtmlTest(unittest.TestCase):
    def test_html_is_self_contained(self):
        f = _finding()
        r = _review()
        html = build_report_html(f, r, "edusrc")
        self.assertIn("<h1>登录接口 SQL 注入</h1>", html)
        self.assertIn("<h2>风险评分分解</h2>", html)
        self.assertIn("证据链", html)
        self.assertIn("</html>", html)


class ReportSnapshotEvidenceTest(unittest.TestCase):
    def _snap_finding(self):
        snap = {
            "ok": True, "url": "https://example.edu.cn/login", "method": "GET",
            "status": 200, "headers": {"Server": "nginx"},
            "body_len": 1024, "elapsed": 0.8, "title": "教务系统登录",
            "visible_text": "欢迎登录，请输入账号密码",
            "body_snippet": "<html><title>教务系统登录</title></html>",
            "captured_at": "2026-08-25T12:00:00+08:00",
        }
        return _finding(evidence={"snapshot": snap})

    def test_sections_include_snapshot(self):
        f = self._snap_finding()
        sec = build_report_sections(f, None, "edusrc")
        ev_items = sec["data"]["evidence"]
        snap_items = [i for i in ev_items if i["kind"] == "snapshot"]
        self.assertEqual(len(snap_items), 1)
        self.assertIn("教务系统登录", snap_items[0]["content"])
        self.assertIn("欢迎登录", snap_items[0]["content"])

    def test_markdown_contains_snapshot(self):
        f = self._snap_finding()
        md = build_report_markdown(f, None, "edusrc")
        self.assertIn("存证快照", md)
        self.assertIn("教务系统登录", md)
        self.assertIn("原始 HTML 片段", md)

    def test_html_contains_snapshot(self):
        f = self._snap_finding()
        html = build_report_html(f, None, "edusrc")
        self.assertIn("存证快照", html)
        self.assertIn("教务系统登录", html)

    def test_docx_contains_snapshot(self):
        f = self._snap_finding()
        data = build_docx_bytes(f, None, "edusrc")
        zf = zipfile.ZipFile(io.BytesIO(data))
        doc = zf.read("word/document.xml").decode("utf-8")
        self.assertIn("存证快照", doc)
        self.assertIn("教务系统登录", doc)


class SnapshotVersionTest(unittest.TestCase):
    def test_snapshot_increments_version(self):
        """无历史时 version=1；有历史时 +1。用假 session 验证递增与快照字段。"""
        calls = []

        class FakeSession:
            async def execute(self, q):
                calls.append(("execute",))
                return SimpleNamespace(scalar_one_or_none=lambda: None)

            def add(self, obj):
                calls.append(("add", obj))

        import asyncio
        f = _finding()
        r = _review()
        session = FakeSession()
        version = asyncio.run(findings._snapshot_report_version(session, f, r, source="user_edit", note="测试"))
        self.assertEqual(version, 1)
        added = [c[1] for c in calls if c[0] == "add"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].version, 1)
        self.assertEqual(added[0].snapshot["title"], "登录接口 SQL 注入")
        self.assertEqual(added[0].snapshot["severity"], "高危")


class ReportPocHttpTest(unittest.TestCase):
    """每步与全局的 curl + yakit/Burp 原始请求包双格式 PoC。"""

    def _poc_finding(self):
        return _finding(
            steps=[
                {"desc": "访问登录接口", "poc": "curl -s 'https://example.edu.cn/api/login'",
                 "poc_http": "GET /api/login HTTP/1.1\nHost: example.edu.cn\n\n"},
                {"desc": "注入万能口令", "poc": "curl -s 'https://example.edu.cn/api/login' -d 'username=admin'",
                 "poc_http": "POST /api/login HTTP/1.1\nHost: example.edu.cn\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin"},
            ],
            poc="curl -s 'https://example.edu.cn/api/login' -d 'username=admin'",
            poc_http="POST /api/login HTTP/1.1\nHost: example.edu.cn\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin",
        )

    def test_sections_keep_per_step_and_global_poc_http(self):
        f = self._poc_finding()
        sec = build_report_sections(f, _review(), "edusrc")
        self.assertEqual(sec["data"]["steps"][0]["poc_http"], "GET /api/login HTTP/1.1\nHost: example.edu.cn")
        self.assertEqual(sec["data"]["poc_http"], "POST /api/login HTTP/1.1\nHost: example.edu.cn\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin")

    def test_markdown_renders_both_formats(self):
        f = self._poc_finding()
        md = build_report_markdown(f, _review(), "edusrc")
        self.assertIn("1. **访问登录接口**", md)
        self.assertIn("curl -s 'https://example.edu.cn/api/login'", md)
        self.assertIn("**请求包（yakit / Burp）**", md)
        self.assertIn("GET /api/login HTTP/1.1", md)
        self.assertIn("**原始请求包（yakit / Burp 可直接导入）**", md)
        self.assertIn("POST /api/login HTTP/1.1", md)

    def test_docx_renders_both_formats(self):
        f = self._poc_finding()
        data = build_docx_bytes(f, _review(), "edusrc")
        zf = zipfile.ZipFile(io.BytesIO(data))
        doc = zf.read("word/document.xml").decode("utf-8")
        self.assertIn("1. 访问登录接口", doc)
        self.assertIn("GET /api/login HTTP/1.1", doc)
        self.assertIn("原始请求包（yakit / Burp 可直接导入）", doc)
        self.assertIn("POST /api/login HTTP/1.1", doc)

    def test_html_renders_both_formats(self):
        f = self._poc_finding()
        html = build_report_html(f, _review(), "edusrc")
        self.assertIn("请求包（yakit / Burp）", html)
        self.assertIn("GET /api/login HTTP/1.1", html)
        self.assertIn("原始请求包（yakit / Burp 可直接导入）", html)
        self.assertIn("POST /api/login HTTP/1.1", html)

    def test_normalize_proposed_edits_keeps_poc_http(self):
        args = {
            "steps": [
                {"desc": "访问登录接口", "poc": "curl -s 'https://x/login'",
                 "poc_http": "GET /login HTTP/1.1\nHost: x\n\n"},
            ],
            "poc": "curl -s 'https://x/login'",
            "poc_http": "GET /login HTTP/1.1\nHost: x\n\n",
        }
        res = findings._normalize_proposed_edits(args)
        self.assertTrue(res["ok"])
        self.assertEqual(res["edits"]["steps"][0]["poc_http"], "GET /login HTTP/1.1\nHost: x")
        self.assertEqual(res["edits"]["poc_http"], "GET /login HTTP/1.1\nHost: x")

    def test_old_string_steps_still_normalize(self):
        f = _finding(steps=["注入万能口令", "绕过认证"])
        sec = build_report_sections(f, _review(), "edusrc")
        self.assertEqual(sec["data"]["steps"], [
            {"desc": "注入万能口令", "poc": "", "poc_http": ""},
            {"desc": "绕过认证", "poc": "", "poc_http": ""},
        ])


if __name__ == "__main__":
    unittest.main()
