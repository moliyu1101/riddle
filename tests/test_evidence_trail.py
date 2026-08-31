"""证据链四层机制回归测试：LLM 提交失败时的数据保全。

1. 证据增量落库：http_request/run_shell 每次调用后真实请求/响应落盘
2. 确定性重建：LLM 提交失败时从证据链重建最小 Finding
3. 大字段回填：_backfill_finding_fields 从证据链补全 raw_request/poc_http/raw_response
4. 切端点软重试复用现有 LLM 重试机制（见 test_worker_llm_soft_retry / client 重试）
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
from app.tools.evidence_trail import build_finding_from_trail, load_trail


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


# ---------- 第2层：确定性重建 ----------

class TestBuildFindingFromTrail:
    def _seed(self, wd: str):
        et.append_trail(
            wd, kind="http_request", target="t",
            url="http://x.com/admin/User/index?offset=0&limit=20", method="GET",
            request="GET /admin/User/index?offset=0&limit=20 HTTP/1.1\nHost: x.com\nCookie: a=1",
            status=200,
            body='{"total":449,"data":[{"name":"z","password_hash":"abc"}]}',
            response_headers={"content-type": "application/json"},
        )

    def test_build_from_trail(self):
        wd = tempfile.mkdtemp()
        self._seed(wd)
        f = build_finding_from_trail(wd, "http://x.com")
        assert f is not None
        assert f["severity_claimed"] == "高危"
        assert f["target_url"]
        assert f["raw_request"] and f["raw_response"]
        assert f["_rebuilt"] is True
        # 无凭证据返回 None
        assert build_finding_from_trail(tempfile.mkdtemp(), "x") is None

    def test_reconstructed_finding_passes_pydantic(self):
        wd = tempfile.mkdtemp()
        self._seed(wd)
        f = build_finding_from_trail(wd, "http://x.com")
        finding = Finding(**f)  # 不应抛 ValidationError
        assert finding.severity_claimed.value == "高危"
        assert len(finding.steps) >= 1


# ---------- 第2层接入：worker 中断时重建兜底 ----------

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


class TestWorkerRebuildRecovery:
    def test_llm_interrupt_rebuilds_from_trail(self):
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
        assert result.findings, "LLM 失败应重建一个 finding"
        assert result.verdict.value == "found"
        assert result.findings[0].raw_request
        kinds = [c.args[0] for c in w._emit.call_args_list]
        assert "finding_submitted" in kinds  # 走标准落库事件，编排层据此落库
        assert "evidence_rebuilt_finding" in kinds

    def test_no_rebuild_when_already_have_findings(self):
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
        assert len(result.findings) == 1  # 已是同一洞，不重复重建

    def test_no_rebuild_when_no_evidence(self):
        ex = FakeExec(tempfile.mkdtemp())
        w = _make_worker(ex)
        w._llm_interrupt_result(rounds=1, error="e", failure_kind="timeout", retry_after=0)
        assert w.findings == []


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