"""模型商预设 + 模型配置智能推荐（连接向导 / temperature 推荐 / 端点池调度预览）。

- LLM_PROVIDER_PRESETS：常见模型商模板，连接向导一键填充 base_url/协议/推荐模型。
- recommend_temperature：按模型类型 + 任务角色推荐 temperature。
- pool_schedule_preview：按权重计算端点池命中分布 + 调度策略说明。
"""
from __future__ import annotations

from typing import Any

# 模型商预设：连接向导一键填充 base_url/协议/推荐模型
LLM_PROVIDER_PRESETS: list[dict[str, Any]] = [
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "desc": "高性价比 · 对话+推理",
        "base_url": "https://api.deepseek.com/v1",
        "protocol": "auto",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "recommended": "deepseek-chat",
        "hint": "官方根地址，无需再加 /v1",
        "tags": ["对话", "推理"],
    },
    {
        "id": "zhipu",
        "name": "智谱 GLM",
        "desc": "国产 · 中文友好",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "protocol": "auto",
        "models": ["glm-4-flash", "glm-4-plus", "glm-4.5", "glm-4.5-air"],
        "recommended": "glm-4-flash",
        "hint": "Coding Plan 填 …/api/coding/paas/v4，无需再加 /v1",
        "tags": ["对话"],
    },
    {
        "id": "volc",
        "name": "火山方舟",
        "desc": "豆包 · 多模型",
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "protocol": "auto",
        "models": ["deepseek-v3", "deepseek-r1", "doubao-1-5-pro-32k-250115"],
        "recommended": "deepseek-v3",
        "hint": "Coding Plan 填 …/api/coding/v3，无需再加 /v1",
        "tags": ["对话", "推理"],
    },
    {
        "id": "kimi",
        "name": "Kimi",
        "desc": "Moonshot · 长上下文",
        "base_url": "https://api.moonshot.cn/v1",
        "protocol": "auto",
        "models": ["kimi-k2-0711-preview", "moonshot-v1-8k", "moonshot-v1-32k"],
        "recommended": "kimi-k2-0711-preview",
        "hint": "官方 v1 端点",
        "tags": ["对话", "推理"],
    },
    {
        "id": "openai",
        "name": "OpenAI",
        "desc": "GPT · 通用",
        "base_url": "https://api.openai.com/v1",
        "protocol": "openai_chat",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
        "recommended": "gpt-4o-mini",
        "hint": "官方 v1 端点",
        "tags": ["对话"],
    },
    {
        "id": "anthropic",
        "name": "Anthropic",
        "desc": "Claude · 推理强",
        "base_url": "https://api.anthropic.com",
        "protocol": "anthropic_messages",
        "models": ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
        "recommended": "claude-3-5-sonnet-20241022",
        "hint": "官方根地址，协议固定 Anthropic Messages",
        "tags": ["推理"],
    },
    {
        "id": "ollama",
        "name": "Ollama 本地",
        "desc": "本地 · 免费离线",
        "base_url": "http://localhost:11434/v1",
        "protocol": "openai_chat",
        "models": ["llama3.1", "qwen2.5", "deepseek-r1"],
        "recommended": "qwen2.5",
        "hint": "本地服务，需先启动 ollama serve",
        "tags": ["本地"],
    },
    {
        "id": "custom",
        "name": "自定义",
        "desc": "任意 OpenAI 兼容端点",
        "base_url": "",
        "protocol": "auto",
        "models": [],
        "recommended": "",
        "hint": "手动填写 base_url / 协议 / 模型",
        "tags": [],
    },
]

_PRESET_BY_ID = {p["id"]: p for p in LLM_PROVIDER_PRESETS}


def provider_preset(preset_id: str) -> dict[str, Any] | None:
    return _PRESET_BY_ID.get(preset_id)


# 模型名关键词 → 基础温度档位（按序匹配，命中即停）
_TEMP_RULES: list[tuple[tuple[str, ...], float, str]] = [
    (("reason", "thinking", "think", "r1", "o1", "o3", "deepseek-reasoner", "k2-thinking", "glm-4.5-thinking"), 0.1, "推理模型：低温保证推理稳定"),
    (("coder", "code", "deepseek-coder", "qwen-coder"), 0.2, "代码模型：低温保证输出准确"),
    (("flash", "mini", "haiku", "lite", "small", "air"), 0.4, "轻量对话模型：适中温度"),
    (("gpt-4o", "gpt-4.1", "claude", "glm-4.5", "kimi-k2", "doubao", "deepseek-v3"), 0.7, "通用大模型：稍高温度兼顾多样"),
]
_DEFAULT_TEMP = 0.4

# 任务角色 → 温度调整
_ROLE_ADJUST: dict[str, float] = {
    "hunt": -0.1,    # 挖洞：确定性优先
    "review": -0.1,  # 审核：确定性优先
    "report": 0.1,   # 报告：行文更自然
}
_ROLE_LABELS = {"hunt": "挖洞", "review": "审核", "report": "报告"}


def recommend_temperature(model: str, role: str = "hunt") -> dict[str, Any]:
    """按模型类型 + 任务角色推荐 temperature（clamp [0,2]，保留 1 位小数）。"""
    low = str(model or "").lower()
    base = _DEFAULT_TEMP
    reason = "通用对话模型"
    for keywords, temp, why in _TEMP_RULES:
        if any(k in low for k in keywords):
            base = temp
            reason = why
            break
    role_key = role if role in _ROLE_ADJUST else "hunt"
    adj = _ROLE_ADJUST[role_key]
    value = round(max(0.0, min(2.0, base + adj)), 1)
    role_label = _ROLE_LABELS.get(role_key, "挖洞")
    direction = "降低" if adj < 0 else ("提高" if adj > 0 else "保持")
    return {
        "temperature": value,
        "base": base,
        "role": role_key,
        "reason": f"{reason}；{role_label}场景{direction}确定性",
    }


def pool_schedule_preview(providers: list[dict[str, Any]]) -> dict[str, Any]:
    """按权重计算端点池命中分布 + 调度策略说明（供前端调度面板展示）。"""
    rows: list[dict[str, Any]] = []
    total = 0
    for p in providers or []:
        weight = max(1, min(100, int(p.get("weight") or 1)))
        enabled = bool(p.get("enabled", True))
        if enabled:
            total += weight
        rows.append({
            "name": str(p.get("name") or "").strip() or "未命名",
            "weight": weight,
            "enabled": enabled,
        })
    for row in rows:
        row["share"] = round(row["weight"] / total, 3) if row["enabled"] and total else 0.0
    return {
        "strategy": "health_first + smooth_weighted_rr",
        "explanation": (
            "先按健康状态分级（健康 > 降级 > 失效），同级内按权重平滑轮询；"
            "权重越大长期命中比例越高，失败端点自动冷却降级、冷却后自动探测恢复。"
        ),
        "total_weight": total,
        "distribution": rows,
    }
