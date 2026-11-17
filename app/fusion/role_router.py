"""按角色配模型 + 技能速查块注入 system prompt。

Pojun 的实战教训：技能是「元工具」，如果 system prompt 里一个字都不提，
模型几乎不会主动调（实测 56k 次工具调用只用了 8 次 skill）。Riddle 的
``app/agents/knowledge.py`` 已有方法论触发词映射，但那是命中后才注入正文，
缺少一份常驻的「有哪些方法论、什么时候用」速查清单。

本模块把 knowledge/ 下的篇目名扫成速查块，和证据纪律、目标纪律一起，
在 worker system prompt 末尾常驻注入。按角色配模型则只做解析与查询，
不改动 ``llm_client_for_task`` 的既有签名与行为。
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.fusion.config import ROLES, load_config, role_model

_KNOWLEDGE_ROOT = Path(__file__).resolve().parents[2] / "knowledge"
_MAX_BLOCK_CHARS = 1400


def resolve_role_model(role: str, overrides: dict | None = None, fallback: str = "") -> str:
    """角色 → 模型名；覆盖值优先于环境变量，都为空则用全局默认模型。"""
    if role not in ROLES:
        return fallback
    overrides = overrides or {}
    value = str(overrides.get(role) or "").strip()
    if value:
        return value
    return role_model(role) or fallback


def role_routing_table(default_model: str = "") -> list[dict]:
    cfg = load_config()
    hints = {
        "planner": "目标拆解与派单，建议强推理模型",
        "worker": "侦察与实证，建议中档、低延迟模型",
        "reviewer": "初审与打回，建议理性、便宜档模型",
        "judge": "拦截裁决，建议便宜档、低延迟模型",
    }
    return [{
        "role": r,
        "model": resolve_role_model(r, fallback=default_model),
        "enabled": cfg.role_routing_enabled,
        "hint": hints[r],
    } for r in ROLES]


def _first_line(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                clean = line.strip().lstrip("#").strip()
                if clean and not clean.startswith("---"):
                    return re.sub(r"\s+", " ", clean)[:80]
    except OSError:
        pass
    return ""


@lru_cache(maxsize=1)
def load_skill_entries() -> tuple[dict, ...]:
    """扫描本地方法论/手册篇目，返回 ({name, category, hint}) 元组。缓存避免每次组 prompt 都读盘。"""
    entries: list[dict] = []
    if not _KNOWLEDGE_ROOT.exists():
        return ()
    for folder in ("rules", "kb"):
        base = _KNOWLEDGE_ROOT / folder
        if not base.is_dir():
            continue
        for path in sorted(base.glob("*.md")):
            try:
                if path.stat().st_size == 0:
                    continue
            except OSError:
                continue
            entries.append({
                "name": path.stem,
                "category": folder,
                "hint": _first_line(path),
            })
    return tuple(entries)


def clear_skill_cache() -> None:
    load_skill_entries.cache_clear()


def _merged_skill_entries() -> list[dict]:
    """合并磁盘内置技能与 DB 动态知识库（用户沉淀/蒸馏篇目优先靠前）。"""
    by_name: dict[str, dict] = {
        row["name"]: dict(row) for row in load_skill_entries()
    }
    dynamic_rows: list[dict] = []
    try:
        from app.agents.knowledge import cached_db_kb_entries

        for row in cached_db_kb_entries():
            name = row.get("name") or ""
            if not name:
                continue
            if not row.get("enabled", True):
                by_name.pop(name, None)
                continue
            hint = re.sub(r"\s+", " ", str(row.get("title") or row.get("keyword") or "")).strip()[:80]
            item = {
                "name": name,
                "category": row.get("category") or "user",
                "origin": row.get("origin") or "user",
                "hint": hint,
            }
            if item["origin"] in ("user", "distilled"):
                dynamic_rows.append(item)
                by_name.pop(name, None)
            else:
                by_name[name] = item
    except Exception:
        pass
    return [*dynamic_rows, *by_name.values()]


def skill_index_block(entries: Any = None, max_chars: int = _MAX_BLOCK_CHARS) -> str:
    """生成常驻速查块；空清单返回空串，绝不往 prompt 塞空标题。"""
    rows = list(entries) if entries is not None else _merged_skill_entries()
    if not rows:
        return ""
    lines = [
        "# 可用方法论速查（按需查阅，不要每轮都读）",
        "下面是本平台沉淀的方法论与测试手册。遇到对应场景时先查阅再动手；",
        "没有对应场景就跳过，不要为了用而用。",
    ]
    used = sum(len(x) + 1 for x in lines)
    for row in rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        hint = str(row.get("hint") or "").strip()
        cat = row.get("category")
        category = "方法论" if cat == "rules" else "实战沉淀" if row.get("origin") in ("user", "distilled") or cat == "user" else "测试手册"
        line = f"- {name}（{category}）{('：' + hint) if hint else ''}"
        if used + len(line) + 1 > max_chars:
            tail = f"- …另有 {len(rows)} 篇，按触发词按需注入正文"
            if used + len(tail) + 1 <= max_chars:
                lines.append(tail)
            break
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines)


_EVIDENCE_DISCIPLINE = """# 证据与影响纪律（融合层）
- 确认漏洞不等于完成：按 L1 信息 → L2 认证/越权 → L3 控制 → L4 数据/资金 推进，
  能往上打一层就继续，判「不可利用」前必须换过两种本质不同的手段并留下失败输出。
- critical/high 必须带可机械复现的凭据：curl 或原始 HTTP 请求包、真实响应/状态码、
  工具命中输出。纯版本匹配、「可能存在」、截图描述都不算证据。
- 结论只写本次真实拿到的响应，不把推断当事实。"""


def fusion_worker_block() -> str:
    """追加到 worker system prompt 的融合层纪律块；总开关关闭时返回空串。"""
    cfg = load_config()
    if not cfg.skill_index_enabled:
        return ""
    parts = [_EVIDENCE_DISCIPLINE]
    index = skill_index_block()
    if index:
        parts.append(index)
    return "\n\n".join(parts)
