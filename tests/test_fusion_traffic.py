"""流量留痕回归：编码/落盘/读取、四类证据角色、去重导入与 executor 钩子。

重点验证两条红线：留痕默认关闭、留痕异常绝不影响 http_request 主链路。
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from app.fusion import traffic_ledger
from app.fusion.config import FusionConfig


@pytest.fixture
def workdir():
    """与仓库其它测试一致用 mkdtemp，避开沙箱下 pytest tmp_path 基目录的 EEXIST。"""
    path = Path(tempfile.mkdtemp(prefix="_fusion_traffic_"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _result(body="hello", status=200):
    return {
        "ok": True, "url": "https://a.example.edu.cn/admin?id=1", "status_code": status,
        "final_method": "GET", "raw_request": "GET /admin?id=1 HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html", "body": body,
        "error": "",
    }


def test_encode_exchange_fields_hash_and_truncation():
    row = traffic_ledger.encode_exchange(_result(), "https://a.example.edu.cn/admin?id=1", "GET", "example.edu.cn")
    assert row["method"] == "GET" and row["status_code"] == 200
    assert row["request_head"].startswith("GET /admin")
    assert row["response_head"].startswith("HTTP/1.1 200")
    assert row["target"] == "example.edu.cn" and row["ok"] is True
    assert len(row["body_sha256"]) == 64
    other = traffic_ledger.encode_exchange(_result(body="changed"), "https://a.example.edu.cn/admin?id=1", "GET")
    assert other["body_sha256"] != row["body_sha256"], "响应变了必须产生新版本指纹"
    big = traffic_ledger.encode_exchange(_result(body="x" * 9000), "u", "POST")
    assert len(big["body"]) == traffic_ledger._MAX_HEAD_CHARS
    # final_method 是重定向/变形后的真实方法，优先于调用时传入的 method
    assert big["method"] == "GET"
    no_final = {k: v for k, v in _result().items() if k != "final_method"}
    assert traffic_ledger.encode_exchange(no_final, "u", "POST")["method"] == "POST"


def test_exchange_hash_is_stable_and_sensitive():
    a = {"method": "GET", "url": "u", "status_code": 200, "request_head": "q", "response_head": "r", "body": "b"}
    assert traffic_ledger.exchange_hash(a) == traffic_ledger.exchange_hash(dict(a))
    b = {**a, "status_code": 403}
    assert traffic_ledger.exchange_hash(a) != traffic_ledger.exchange_hash(b)


def test_jsonl_roundtrip_skips_corrupt_lines_and_honours_limit(workdir):
    assert traffic_ledger.read_jsonl(workdir) == []
    for i in range(3):
        assert traffic_ledger.append_jsonl(workdir, {"i": i, "body_sha256": f"s{i}"}) is True
    (workdir / traffic_ledger.JSONL_NAME).write_text(
        '{"i": 0}\nBROKEN LINE\n{"i": 1}\n', encoding="utf-8"
    )
    rows = traffic_ledger.read_jsonl(workdir)
    assert [r["i"] for r in rows] == [0, 1]
    assert [r["i"] for r in traffic_ledger.read_jsonl(workdir, limit=1)] == [0]


def test_capture_sync_never_raises_on_bad_path(workdir):
    blocker = workdir / "file"
    blocker.write_text("x", encoding="utf-8")
    assert traffic_ledger.capture_sync(blocker / "no" / "dir", _result(), "u", "GET") is False
    assert traffic_ledger.capture_sync(None, {}, "u", "GET") is False


def test_classify_role_all_four_cases():
    assert traffic_ledger.classify_role({"ok": False, "status_code": 200}) == "supporting"
    assert traffic_ledger.classify_role({"ok": True, "status_code": 200}) == "proof"
    assert traffic_ledger.classify_role({"ok": True, "status_code": 403}) == "baseline"
    assert traffic_ledger.classify_role({"ok": True, "status_code": 200}, has_finding=True) == "verification"
    assert traffic_ledger.classify_role({"ok": True, "status_code": 500}) == "supporting"


def test_build_db_rows_dedups_by_sha_and_url():
    row = traffic_ledger.encode_exchange(_result(), "https://a.example.edu.cn/x", "GET")
    rows = traffic_ledger.build_db_rows([row, dict(row), {**row, "url": "https://a.example.edu.cn/y"}], "T1")
    assert len(rows) == 2
    assert all(r["task_id"] == "T1" for r in rows)
    assert all(r["role"] in traffic_ledger.ROLES for r in rows)
    assert all(len(r["body_sha256"]) == 64 for r in rows)
    assert traffic_ledger.build_db_rows([None, "bad"], "T1") == []


def test_bindings_for_finding_groups_by_role():
    rows = [
        {"finding_id": "f1", "role": "proof", "id": "1"},
        {"finding_id": "f1", "role": "baseline", "id": "2"},
        {"finding_id": "f2", "role": "proof", "id": "3"},
        {"finding_id": "f1", "role": "unknown", "id": "4"},
    ]
    out = traffic_ledger.bindings_for_finding(rows, "f1")
    assert {r: len(v) for r, v in out.items() if v} == {"proof": 1, "baseline": 1, "unknown": 1}
    assert all(r["id"] != "3" for group in out.values() for r in group)
    assert traffic_ledger.bindings_for_finding([], "f1") == {r: [] for r in traffic_ledger.ROLES}


def _executor(workdir, monkeypatch):
    from app.tools import executor as ex_mod

    ex = ex_mod.ToolExecutor("example.edu.cn", work_dir=str(workdir))
    monkeypatch.setattr(ex, "_http_request_once", lambda *a, **kw: _result())
    monkeypatch.setattr(ex, "_waf_perceive", lambda result, url: result)
    monkeypatch.setattr(ex, "_maybe_auto_waf_bypass", lambda result, *a, **kw: result)
    monkeypatch.setattr(ex_mod, "check_task_forbidden", lambda *a, **kw: None)
    monkeypatch.setattr(ex_mod, "check_http_request", lambda *a, **kw: None)
    monkeypatch.setattr(ex_mod, "_append_evidence_trail", lambda *a, **kw: None)
    return ex


def _request(ex, *, enabled):
    """每次调用单独打桩：两个 executor 共享同一个模块级 load_config，不能靠构造时打桩。"""
    from app.fusion import config as cfg_mod

    with patch.object(cfg_mod, "load_config",
                      return_value=replace(FusionConfig(), traffic_enabled=enabled)):
        return ex.http_request("https://a.example.edu.cn/x")


def test_executor_hook_writes_only_when_enabled(workdir, monkeypatch):
    on_dir, off_dir = workdir / "on", workdir / "off"
    on = _executor(on_dir, monkeypatch)
    off = _executor(off_dir, monkeypatch)
    assert _request(on, enabled=True)["ok"] is True
    assert _request(off, enabled=False)["ok"] is True
    on_rows = traffic_ledger.read_jsonl(on.work_dir)
    assert len(on_rows) == 1 and on_rows[0]["status_code"] == 200
    assert not (off.work_dir / traffic_ledger.JSONL_NAME).exists(), "默认关闭时不得写留痕文件"


def test_executor_hook_failure_does_not_break_request(workdir, monkeypatch):
    from app.fusion import config as cfg_mod

    ex = _executor(workdir, monkeypatch)
    with patch.object(cfg_mod, "load_config",
                      return_value=replace(FusionConfig(), traffic_enabled=True)), \
         patch.object(traffic_ledger, "capture_sync", side_effect=RuntimeError("ledger exploded")):
        out = ex.http_request("https://a.example.edu.cn/x")
    assert out["ok"] is True, "留痕层异常必须被吞掉，主请求正常返回"


def test_jsonl_is_valid_json_lines(workdir):
    traffic_ledger.capture_sync(workdir, _result(), "https://a.example.edu.cn/x", "GET", "example.edu.cn")
    lines = (workdir / traffic_ledger.JSONL_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert isinstance(json.loads(lines[0]), dict)
