"""融合层：目标闸门 / 证据闸门 单元测试（纯函数，离线、不碰数据库）。"""
from __future__ import annotations

import pytest

from app.agents.prompts import worker_system_prompt
from app.fusion import evidence_gate, goal_gate


def _goal(**kw):
    base = {
        "title": "未授权接口返回业务数据",
        "criteria": "匿名 GET 返回 200 且响应 JSON 含业务字段，可用 curl 复现",
        "kind": "existence",
    }
    base.update(kw)
    return base


def test_validate_goals_accepts_verifiable_criteria():
    goals, errors = goal_gate.validate_goals([_goal()])
    assert errors == []
    assert goals[0]["kind"] == "existence"
    assert goals[0]["id"]


def test_validate_goals_rejects_process_only_goal():
    _, errors = goal_gate.validate_goals([_goal(title="发现漏洞")])
    assert any("过程动作" in e for e in errors)


def test_validate_goals_rejects_unverifiable_criteria():
    _, errors = goal_gate.validate_goals([_goal(criteria="确认系统整体安全性")])
    assert any("可核验信号" in e for e in errors)


def test_validate_goals_rejects_empty_and_duplicate_ids():
    assert goal_gate.validate_goals([])[1]
    dup = [_goal(id="g1"), _goal(id="g1")]
    assert any("id 重复" in e for e in goal_gate.validate_goals(dup)[1])


def test_capability_goal_rejects_fact_and_low_finding():
    goals, _ = goal_gate.validate_goals([_goal(
        title="取得目标主机命令执行能力", criteria="命令输出回显 uid=0 的 curl 结果", kind="capability"
    )])
    low = [{"severity_claimed": "low", "title": "疑似命令执行"}]
    facts = [{"summary": "疑似存在命令执行入口"}]
    result = goal_gate.evaluate(goals, low, facts)
    assert result["goal_met"] is False
    assert result["terminal_state"] == "incomplete"
    assert "只接受 high/critical" in result["unmet"][0]["reason"]


def test_capability_goal_accepts_high_finding():
    goals, _ = goal_gate.validate_goals([_goal(
        title="取得目标主机命令执行能力", criteria="命令输出回显 uid=0 的 curl 结果", kind="capability"
    )])
    high = [{"severity_claimed": "high", "title": "命令执行已实证"}]
    assert goal_gate.evaluate(goals, high)["goal_met"] is True


def test_existence_goal_accepts_fact():
    goals, _ = goal_gate.validate_goals([_goal(match=["未授权"])])
    facts = [{"summary": "未授权接口已确认"}]
    assert goal_gate.evaluate(goals, [], facts)["goal_met"] is True


def test_terminal_state_is_honest_even_when_upstream_claims_done():
    goals, _ = goal_gate.validate_goals([_goal(), _goal(id="g2", title="越权读取他人对象", criteria="响应 200 且返回非本人字段")])
    result = goal_gate.evaluate(goals, [])
    assert result["summary"] == "0/2 目标达成"
    assert goal_gate.terminal_state(result, proposed="done") == "incomplete"
    assert goal_gate.terminal_state(result, proposed="done") != "done"


def test_criteria_status_codes_extracted():
    goals, _ = goal_gate.validate_goals([_goal(criteria="匿名请求返回 status: 200 且含业务字段")])
    assert "200" in goal_gate.criteria_status_codes(goals[0])


def _finding(**kw):
    base = {"severity_claimed": "critical", "title": "远程命令执行", "vuln_type": "rce"}
    base.update(kw)
    return base


def test_evidence_gate_blocks_critical_without_mechanical_proof():
    result = evidence_gate.check_finding(_finding(description="该组件可能存在命令执行风险"))
    assert result["allowed"] is False
    assert any("机械可复现凭据" in r for r in result["reasons"])


def test_evidence_gate_blocks_critical_when_impact_too_low():
    result = evidence_gate.check_finding(_finding(
        title="信息泄露", vuln_type="info_leak", poc="curl http://target/x", raw_response="HTTP/1.1 200 OK"
    ))
    assert result["impact_level"] == "L1"
    assert result["allowed"] is False
    assert any("影响层级" in r for r in result["reasons"])


def test_evidence_gate_allows_critical_with_packet_and_l3():
    result = evidence_gate.check_finding(_finding(
        poc="curl -s 'http://target/run?cmd=id'",
        raw_response="HTTP/1.1 200 OK\nuid=0(root)",
        poc_http="GET /run?cmd=id HTTP/1.1\nHost: target",
    ))
    assert result["allowed"] is True
    assert result["impact_level"] == "L3"
    assert "可执行请求命令" in result["evidence"]
    assert "原始 HTTP 请求包" in result["evidence"]


def test_high_requires_l2_and_low_is_never_blocked():
    assert evidence_gate.check_finding(_finding(severity_claimed="low", title="指纹泄露"))["allowed"] is True
    high = evidence_gate.check_finding(_finding(
        severity_claimed="high", title="越权读取他人订单", vuln_type="idor",
        poc="curl -s http://target/order/2", raw_response="HTTP/1.1 200 OK"
    ))
    assert high["allowed"] is True
    assert high["impact_level"] == "L2"


def test_evaluate_findings_batch_counts():
    result = evidence_gate.evaluate_findings([
        _finding(description="纯推断，无任何凭据"),
        _finding(poc="curl http://x", raw_response="HTTP/1.1 200 uid=0(root)"),
    ])
    assert result["total"] == 2
    assert result["blocked"] >= 1
    assert "levels" in result


def test_fusion_block_is_appended_to_worker_prompt():
    plain = worker_system_prompt(False, None, src_rules=None)
    with_block = worker_system_prompt(False, None, src_rules=None, fusion_block="## 融合纪律\n- 必须有实锤")
    assert with_block.startswith(plain.rstrip())
    assert "融合纪律" in with_block
    assert with_block.endswith("\n")


def test_worker_prompt_without_fusion_block_is_unchanged():
    assert worker_system_prompt(False, None, src_rules=None, fusion_block="") == worker_system_prompt(False, None)
