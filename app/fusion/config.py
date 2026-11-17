"""融合层配置：环境变量为基线，设置页写入的 DB overlay 优先。

存储位置：``SystemSettings.defaults["fusion"]``（复用现有单行配置表，不新增表）。
写入走 ``settings_service.update_settings``，它内部会 ``refresh_cache``，因此
worker / executor 通过同步的 ``effective_settings()`` 立即读到新值，无需重启。

优先级：融合页写入值 > .env > 内置默认。
安全默认值：**硬闸门与流量留痕默认关闭**，只做提示词纪律与只读试算，
保证存量任务与全量回归的默认行为完全不变。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace

_TRUE = {"1", "true", "yes", "on"}
ROLES: tuple[str, ...] = ("planner", "worker", "reviewer", "judge")

# 前端可写字段白名单：密钥不走这里，避免明文落库与回显
EDITABLE_BOOL = (
    "evidence_gate_hard", "scope_guard_hard", "goal_gate_enabled",
    "skill_index_enabled", "role_routing_enabled", "intel_sync_enabled",
    "traffic_enabled", "graphs_enabled", "report_enabled",
)
EDITABLE_INT = ("intel_lookback_days", "intel_sync_interval_hours")
EDITABLE_FLOAT = ("intel_fastlane_cvss", "intel_timeout")
EDITABLE = (*EDITABLE_BOOL, *EDITABLE_INT, *EDITABLE_FLOAT, "role_models")


def _flag(key: str, default: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


def _number(key: str, default: float, lo: float, hi: float, *, as_int: bool = False):
    try:
        val = float(os.getenv(key, "").strip() or default)
    except (TypeError, ValueError):
        val = float(default)
    val = max(lo, min(hi, val))
    return int(val) if as_int else val


@dataclass(frozen=True)
class FusionConfig:
    evidence_gate_hard: bool = False
    scope_guard_hard: bool = False
    goal_gate_enabled: bool = True
    skill_index_enabled: bool = True
    role_routing_enabled: bool = True
    intel_sync_enabled: bool = True
    traffic_enabled: bool = False
    graphs_enabled: bool = True
    report_enabled: bool = True
    intel_lookback_days: int = 7
    intel_sync_interval_hours: int = 0
    intel_fastlane_cvss: float = 9.0
    intel_timeout: float = 12.0
    nvd_api_key: str = ""
    role_models: dict = field(default_factory=dict)


def _env_role_models() -> dict:
    return {r: os.getenv(f"FUSION_ROLE_MODEL_{r.upper()}", "").strip() for r in ROLES}


def _db_overlay() -> dict:
    """从 settings_service 的内存缓存读融合配置；任何异常都退回纯 env 配置。"""
    try:
        from app.settings_service import effective_settings
        raw = (effective_settings().get("defaults") or {}).get("fusion") or {}
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _coerce(name: str, value, base: FusionConfig):
    if name in EDITABLE_BOOL:
        return value if isinstance(value, bool) else str(value).strip().lower() in _TRUE
    if name in EDITABLE_INT:
        # 与 .env 的 _number 同一组上下界，避免 DB overlay 绕过数值约束
        lo, hi = (0, 720) if name == "intel_sync_interval_hours" else (1, 90)
        try:
            return max(lo, min(hi, int(value)))
        except (TypeError, ValueError):
            return getattr(base, name)
    if name in EDITABLE_FLOAT:
        lo, hi = (0.0, 10.0) if name == "intel_fastlane_cvss" else (1.0, 60.0)
        try:
            return max(lo, min(hi, float(value)))
        except (TypeError, ValueError):
            return getattr(base, name)
    if name == "role_models" and isinstance(value, dict):
        return {r: str(value.get(r) or "").strip() for r in ROLES}
    return getattr(base, name)


def load_config(overlay: dict | None = None) -> FusionConfig:
    base = FusionConfig(
        evidence_gate_hard=_flag("FUSION_EVIDENCE_GATE_HARD", False),
        scope_guard_hard=_flag("FUSION_SCOPE_GUARD_HARD", False),
        goal_gate_enabled=_flag("FUSION_GOAL_GATE", True),
        skill_index_enabled=_flag("FUSION_SKILL_INDEX", True),
        role_routing_enabled=_flag("FUSION_ROLE_ROUTING", True),
        intel_sync_enabled=_flag("FUSION_INTEL_SYNC", True),
        traffic_enabled=_flag("FUSION_TRAFFIC", False),
        graphs_enabled=_flag("FUSION_GRAPHS", True),
        report_enabled=_flag("FUSION_REPORT", True),
        intel_lookback_days=_number("FUSION_INTEL_LOOKBACK_DAYS", 7, 1, 90, as_int=True),
        intel_sync_interval_hours=_number("FUSION_INTEL_SYNC_INTERVAL_HOURS", 0, 0, 720, as_int=True),
        intel_fastlane_cvss=_number("FUSION_INTEL_FASTLANE_CVSS", 9.0, 0.0, 10.0),
        intel_timeout=_number("FUSION_INTEL_TIMEOUT", 12.0, 1.0, 60.0),
        nvd_api_key=os.getenv("NVD_API_KEY", "").strip(),
        role_models=_env_role_models(),
    )
    ov = _db_overlay() if overlay is None else (overlay or {})
    if not ov:
        return base
    allowed = {f.name for f in fields(FusionConfig)}
    clean = {k: _coerce(k, v, base) for k, v in ov.items() if k in allowed and v is not None}
    return replace(base, **clean)


def writable_patch(payload: dict, current: dict | None = None) -> dict:
    """把前端提交的配置收敛成可落库的白名单 patch；非法键与密钥一律丢弃。"""
    if not isinstance(payload, dict):
        return {}
    base = load_config()
    current = current or {}
    out: dict = {}
    for key in EDITABLE:
        if key not in payload:
            continue
        value = payload[key]
        if key == "role_models":
            if isinstance(value, dict):
                out[key] = {r: str(value.get(r) or "").strip() for r in ROLES}
            continue
        out[key] = _coerce(key, value, base)
    return out


def role_model(role: str, cfg: FusionConfig | None = None) -> str:
    """按角色取模型覆盖值；未配置返回空串（沿用任务/全局默认模型）。"""
    if role not in ROLES:
        return ""
    cfg = cfg or load_config()
    return (cfg.role_models or {}).get(role, "")


def role_models(cfg: FusionConfig | None = None) -> dict[str, str]:
    cfg = cfg or load_config()
    return {r: role_model(r, cfg) for r in ROLES}


def public_config(overlay: dict | None = None) -> dict:
    """给前端展示的安全子集：绝不回传 NVD_API_KEY 明文。"""
    cfg = load_config(overlay)
    return {
        "evidence_gate_hard": cfg.evidence_gate_hard,
        "scope_guard_hard": cfg.scope_guard_hard,
        "goal_gate_enabled": cfg.goal_gate_enabled,
        "skill_index_enabled": cfg.skill_index_enabled,
        "role_routing_enabled": cfg.role_routing_enabled,
        "intel_sync_enabled": cfg.intel_sync_enabled,
        "traffic_enabled": cfg.traffic_enabled,
        "graphs_enabled": cfg.graphs_enabled,
        "report_enabled": cfg.report_enabled,
        "intel_lookback_days": cfg.intel_lookback_days,
        "intel_sync_interval_hours": cfg.intel_sync_interval_hours,
        "intel_fastlane_cvss": cfg.intel_fastlane_cvss,
        "intel_timeout": cfg.intel_timeout,
        "nvd_api_key_configured": bool(cfg.nvd_api_key),
        "role_models": role_models(cfg),
        "roles": list(ROLES),
        "editable": list(EDITABLE),
    }
