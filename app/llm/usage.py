"""任务级 LLM token 用量计数。

运行态计数足够支撑看板实时观察；进程重启后清零，不参与审计结算。
"""
from __future__ import annotations

from threading import Lock
from time import time
from typing import Any

_LOCK = Lock()
_USAGE: dict[str, dict[str, Any]] = {}
_USAGE_MAX_TASKS = 200  # 任务停止/删除会主动清理；上限兜底异常路径泄漏


def record_usage(task_id: str | None, model: str, prompt_tokens: int = 0,
                 completion_tokens: int = 0, total_tokens: int = 0,
                 cache_hit_tokens: int = 0, cache_miss_tokens: int = 0) -> None:
    if not task_id:
        return
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    total = max(0, int(total_tokens or 0)) or (prompt + completion)
    cache_hit = max(0, int(cache_hit_tokens or 0))
    cache_miss = max(0, int(cache_miss_tokens or 0))
    with _LOCK:
        row = _USAGE.setdefault(task_id, {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cache_hit_tokens": 0,
            "cache_miss_tokens": 0,
            "requests": 0,
            "model": model,
            "updated_at": None,
        })
        row["prompt_tokens"] += prompt
        row["completion_tokens"] += completion
        row["total_tokens"] += total
        row["cache_hit_tokens"] = row.get("cache_hit_tokens", 0) + cache_hit
        row["cache_miss_tokens"] = row.get("cache_miss_tokens", 0) + cache_miss
        row["requests"] += 1
        row["model"] = model
        row["updated_at"] = time()
        # 容量兜底：超限时淘汰最旧的行（正常路径由 clear_usage 主动清理）
        while len(_USAGE) > _USAGE_MAX_TASKS:
            oldest = min(_USAGE, key=lambda k: _USAGE[k].get("updated_at") or 0)
            _USAGE.pop(oldest, None)


def clear_usage(task_id: str | None) -> None:
    """任务停止/删除时清理其用量行（否则长驻进程内只增不清）。"""
    if not task_id:
        return
    with _LOCK:
        _USAGE.pop(task_id, None)


def usage_snapshot(task_id: str | None, model: str = "") -> dict[str, Any]:
    if not task_id:
        return _empty(model)
    with _LOCK:
        row = dict(_USAGE.get(task_id) or {})
    if not row:
        return _empty(model)
    if model and not row.get("model"):
        row["model"] = model
    return row


def _empty(model: str = "") -> dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
        "requests": 0,
        "model": model,
        "updated_at": None,
    }
