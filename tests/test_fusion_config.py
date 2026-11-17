"""融合层配置回归：.env 基线 / DB overlay 优先级 / 白名单写入 / 密钥不外泄。

这些测试全部走纯函数或显式 overlay，不初始化数据库、不改 settings_service 缓存，
避免与同会话里其它测试的全局态互相污染。
"""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

import pytest

from app.fusion import config

_ENV_KEYS = (
    "FUSION_EVIDENCE_GATE_HARD", "FUSION_SCOPE_GUARD_HARD", "FUSION_GOAL_GATE",
    "FUSION_SKILL_INDEX", "FUSION_ROLE_ROUTING", "FUSION_INTEL_SYNC",
    "FUSION_TRAFFIC", "FUSION_GRAPHS", "FUSION_REPORT",
    "FUSION_INTEL_LOOKBACK_DAYS", "FUSION_INTEL_FASTLANE_CVSS", "FUSION_INTEL_TIMEOUT",
    "NVD_API_KEY", "FUSION_ROLE_MODEL_PLANNER", "FUSION_ROLE_MODEL_WORKER",
    "FUSION_ROLE_MODEL_REVIEWER", "FUSION_ROLE_MODEL_JUDGE",
)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_defaults_keep_existing_behaviour_unchanged():
    cfg = config.load_config(overlay={})
    # 两个硬闸门与流量留痕默认关闭：存量任务行为不受融合层影响
    assert cfg.evidence_gate_hard is False
    assert cfg.scope_guard_hard is False
    assert cfg.traffic_enabled is False
    # 只做提示词纪律/只读试算的能力默认开启
    assert cfg.goal_gate_enabled is True
    assert cfg.skill_index_enabled is True
    assert cfg.role_routing_enabled is True
    assert cfg.intel_sync_enabled is True
    assert cfg.graphs_enabled is True
    assert cfg.report_enabled is True
    assert cfg.intel_lookback_days == 7
    assert cfg.intel_fastlane_cvss == 9.0
    assert cfg.intel_timeout == 12.0


def test_env_is_the_baseline(monkeypatch):
    monkeypatch.setenv("FUSION_TRAFFIC", "1")
    monkeypatch.setenv("FUSION_REPORT", "off")
    monkeypatch.setenv("FUSION_INTEL_LOOKBACK_DAYS", "30")
    cfg = config.load_config(overlay={})
    assert cfg.traffic_enabled is True
    assert cfg.report_enabled is False
    assert cfg.intel_lookback_days == 30


def test_overlay_wins_over_env(monkeypatch):
    monkeypatch.setenv("FUSION_TRAFFIC", "1")
    cfg = config.load_config(overlay={"traffic_enabled": False, "graphs_enabled": False})
    assert cfg.traffic_enabled is False
    assert cfg.graphs_enabled is False


def test_auto_overlay_reads_settings_service_cache():
    payload = {"defaults": {"fusion": {"evidence_gate_hard": True, "traffic_enabled": True}}}
    with patch("app.settings_service.effective_settings", return_value=payload):
        cfg = config.load_config()
    assert cfg.evidence_gate_hard is True
    assert cfg.traffic_enabled is True


def test_auto_overlay_failure_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("FUSION_GOAL_GATE", "0")
    with patch("app.settings_service.effective_settings", side_effect=RuntimeError("db down")):
        cfg = config.load_config()
    assert cfg.goal_gate_enabled is False
    assert cfg.evidence_gate_hard is False


def test_writable_patch_whitelist_and_coercion():
    patch_data = config.writable_patch({
        "traffic_enabled": "on",
        "evidence_gate_hard": "false",
        "intel_lookback_days": "14",
        "intel_timeout": "20",
        "role_models": {"worker": " model-b ", "unknown_role": "x"},
        "nvd_api_key": "must-not-persist",
        "not_a_real_key": 1,
    })
    assert patch_data["traffic_enabled"] is True
    assert patch_data["evidence_gate_hard"] is False
    assert patch_data["intel_lookback_days"] == 14
    assert patch_data["intel_timeout"] == 20.0
    assert patch_data["role_models"] == {
        "planner": "", "worker": "model-b", "reviewer": "", "judge": "",
    }
    assert "nvd_api_key" not in patch_data
    assert "not_a_real_key" not in patch_data


def test_writable_patch_clamps_numbers_like_env():
    out = config.writable_patch({
        "intel_lookback_days": 9999,
        "intel_fastlane_cvss": 99,
        "intel_timeout": 0.01,
    })
    assert out["intel_lookback_days"] == 90
    assert out["intel_fastlane_cvss"] == 10.0
    assert out["intel_timeout"] == 1.0
    bad = config.writable_patch({"intel_lookback_days": "abc"})
    assert bad["intel_lookback_days"] == config.load_config(overlay={}).intel_lookback_days


def test_writable_patch_rejects_non_dict():
    assert config.writable_patch(None) == {}
    assert config.writable_patch([]) == {}
    assert config.writable_patch({}) == {}


def test_public_config_never_leaks_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "super-secret-value")
    out = config.public_config(overlay={})
    assert out["nvd_api_key_configured"] is True
    assert "nvd_api_key" not in out
    assert "super-secret-value" not in str(out)
    assert set(config.EDITABLE).issubset(set(out["editable"]))
    assert out["roles"] == list(config.ROLES)


def test_role_model_lookup():
    cfg = replace(config.load_config(overlay={}), role_models={"worker": "m-fast", "judge": "m-strong"})
    assert config.role_model("worker", cfg) == "m-fast"
    assert config.role_model("judge", cfg) == "m-strong"
    assert config.role_model("planner", cfg) == ""
    assert config.role_model("not-a-role", cfg) == ""
    assert config.role_models(cfg) == {
        "planner": "", "worker": "m-fast", "reviewer": "", "judge": "m-strong",
    }
