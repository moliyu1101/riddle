"""证据链收集与回填回归测试。

1. 证据增量落库：http_request/run_shell 每次调用后真实请求/响应落盘（与 LLM 解耦）
2. 大字段回填：_backfill_finding_fields 从证据链补全 raw_request/poc_http/raw_response
3. 切端点软重试复用现有 LLM 重试机制（见 test_worker_llm_soft_retry / client 重试）

注意：不在此处重建漏洞。LLM 超时不自动判定漏洞，仅保留断点续挖进度，
由下次续挖的 LLM 自行判断并正式提交，从机制上杜绝 LLM 超时导致误报假洞。
"""
from __future__ import annotations

import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.agents.worker import Worker
from app.schemas import Finding, Severity
from app.tools import evidence_trail as et
from app.tools.evidence_trail import load_trail


# ---------- 第1层：证据增量落库 ----------

class TestEvidenceTrailAppend:
    def test_append_and_load(self):
        wd = tempfile.mkdtemp()
        et.append_trail(
            wd, kind="http_request", url="http://x/a", method="GET",
            request="GET /a HTTP/1.1", status=200, body="body",
            response_headers={"content-type": "text/html"},
        )
        et.append_trail(wd, kind="run_shell", output="cmd out")
        trail = et.load_trail(wd)
        assert len(trail) == 2
        assert trail[0]["kind"] == "http_request"
        assert trail[0]["status"] == 200
        assert trail[1]["kind"] == "run_shell"

    def test_big_body_clipped(self):
        wd = tempfile.mkdtemp()
        et.append_trail(wd, kind="http_request", body="x" * 500000)
        rec = et.load_trail(wd)[0]
        assert len(rec["body"]) < 500000  # 被裁剪，显著小于原始输入，防撑爆 work_dir

    def test_append_failure_silent(self):
        # 非法 work_dir（None）不抛异常
        et.append_trail(None, kind="http_request")  # 不应抛
        et.append_trail(Path("Z:/no/such/dir"), kind="http_request")  # 不应抛


# ---------- LLM 中断不再自动重建漏洞，仅保留断点续挖 ----------

class FakeExec:
    def __init__(self, work_dir: str):
        self.work_dir = Path(work_dir)

    def export_resume_state(self) -> dict:
        return {
            "worker_notes": "n", "cognition": {"confirmed": [], "excluded": [], "leads": [], "plan": ""},
            "session_cookies": {}, "session_headers": {},
            "shell_cwd": "", "shell_env": {}, "shell_history": [],
        }


def _make_worker(ex, findings=None):
    w = Worker.__new__(Worker)
    w.target = "http://x.com"
    w._enterprise = False
    w.findings = findings or []
    w.executor = ex
    w.cancel_event = threading.Event()
    w._emit = Mock()
    w._probed_urls = set()
    w.deepen_context = None
    w._intel_block = Mock(return_value="")
    w._duplicate_block = Mock(return_value="")
    w._dup_matches = lambda cand: (False, [])
    return w


class TestWorkerNoRebuildOnInterrupt:
    def test_llm_interrupt_does_not_rebuild_finding(self):
        # 即使盘上已有证据，LLM 中断后也绝不自动生成漏洞（防止把非漏洞硬判成高危）
        wd = tempfile.mkdtemp()
        et.append_trail(
            wd, kind="http_request", url="http://x.com/a", method="GET",
            request="GET /a HTTP/1.1", status=200, body="secret",
            response_headers={"content-type": "text/plain"},
        )
        ex = FakeExec(wd)
        w = _make_worker(ex)
        result = w._llm_interrupt_result(
            rounds=12, error="LLM 请求超时", failure_kind="timeout", retry_after=0,
        )
        assert result.findings == [], "LLM 中断绝不能自动重建漏洞（避免误报假洞）"
        assert result.verdict.value == "error"
        assert result.resume_context, "断点续挖进度必须保留"
        emitted = [c.args[0] for c in w._emit.call_args_list]
        assert "finding_submitted" not in emitted, "不应发出落库事件"
        assert "evidence_rebuilt_finding" not in emitted

    def test_existing_findings_preserved_on_interrupt(self):
        wd = tempfile.mkdtemp()
        et.append_trail(
            wd, kind="http_request", url="http://x.com/a", method="GET",
            request="GET /a HTTP/1.1", status=200, body="secret",
            response_headers={},
        )
        ex = FakeExec(wd)
        existing = Finding(
            vuln_type="unauthorized_access", title="t", severity_claimed=Severity.high,
            target_url="http://x.com/", description="d", steps=["s"], poc="p",
        )
        w = _make_worker(ex, findings=[existing])
        result = w._llm_interrupt_result(
            rounds=12, error="timeout", failure_kind="timeout", retry_after=0,
        )
        assert len(result.findings) == 1  # 既有明文发现的洞保留，不删

    def test_no_resume_when_nothing(self):
        ex = FakeExec(tempfile.mkdtemp())
        w = _make_worker(ex)
        result = w._llm_interrupt_result(rounds=1, error="e", failure_kind="timeout", retry_after=0)
        assert result.findings == []


# ---------- 第3层：大字段确定性回填 ----------

class TestBackfillFindingFields:
    def _wd_with_evidence(self, url: str) -> str:
        wd = tempfile.mkdtemp()
        et.append_trail(
            wd, kind="http_request", url=url, method="GET",
            request=f"GET {url.split('://')[-1]} HTTP/1.1\nHost: h\nCookie: s=1",
            status=200, body="secret-data",
            response_headers={"content-type": "application/json"},
        )
        return wd

    def test_backfills_missing_large_fields(self):
        wd = self._wd_with_evidence("https://s.example.edu.cn/api/users?id=5")
        w = _make_worker(FakeExec(wd))
        finding = Finding(
            vuln_type="idor", title="t", severity_claimed=Severity.high,
            target_url="https://s.example.edu.cn/api/users?id=5",
            description="d", steps=["s"], poc="p",
        )
        w._backfill_finding_fields(finding)
        assert finding.raw_request
        assert finding.poc_http == finding.raw_request
        assert finding.raw_response
        assert "HTTP/1.1 200" in finding.raw_response

    def test_does_not_overwrite_existing_fields(self):
        wd = self._wd_with_evidence("https://s.example.edu.cn/a")
        w = _make_worker(FakeExec(wd))
        finding = Finding(
            vuln_type="idor", title="t", severity_claimed=Severity.high,
            target_url="https://s.example.edu.cn/a",
            description="d", steps=["s"], poc="p",
            raw_request="KEEP-ME", raw_response="RESP", poc_http="POC",
        )
        w._backfill_finding_fields(finding)
        assert finding.raw_request == "KEEP-ME"
        assert finding.raw_response == "RESP"
        assert finding.poc_http == "POC"

    def test_does_not_backfill_different_target(self):
        wd = self._wd_with_evidence("https://other.com/a")
        w = _make_worker(FakeExec(wd))
        finding = Finding(
            vuln_type="idor", title="t", severity_claimed=Severity.high,
            target_url="https://s.example.edu.cn/b",
            description="d", steps=["s"], poc="p",
        )
        w._backfill_finding_fields(finding)
        assert not finding.raw_request  # 不同目标不回填，防串洞