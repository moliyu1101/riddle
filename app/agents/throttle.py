"""多目标并发智能节流（纯逻辑、可单测）。

把 orchestrator 的 worker 并发上限从「固定 min(task.concurrency, 全局上限)」升级为
「按任务池水位 / LLM 健康度 / 目标机构扎堆度 动态调整」，避免：
- LLM 全池冷却/限流时仍满并发撞墙（持续 429/冷却空转）；
- 队列目标很少时仍按满并发起（小任务浪费）；
- 同机构目标扎堆时重复探测、互相干扰。

设计纪律：
- 纯函数、无 IO、确定性、可单测；所有降级因子保守叠加（取最小），保证 >= 1。
- 只降不升：返回的上限是「本轮最多起多少个」，实际 spawn 仍由队列 pop 决定。
"""
from __future__ import annotations

import math

# 同机构扎堆阈值：queued 目标里同一 school/org 占比达到该值视为扎堆。
SAME_ORG_RATIO_THRESHOLD = 0.6
# 多个 LLM 端点同时冷却时视为「provider 不稳定」。
PROVIDER_COOLDOWN_THRESHOLD = 2


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def compute_effective_cap(
    user_concurrency: int,
    global_max: int,
    queued_count: int,
    llm_under_cooldown: bool = False,
    llm_provider_cooldowns: int = 0,
    same_org_ratio: float = 0.0,
) -> tuple[int, list[str]]:
    """计算本轮 worker 有效并发上限。

    返回 (cap, reasons)：cap 为动态调整后的上限（>=1），reasons 为触发降级的
    可读原因列表（未降级时为空）。

    规则（按序叠加，取各因子后的最小值，保守）：
    1. 基础 = min(user_concurrency, global_max)；
    2. LLM 全池冷却 → 砍半；
    3. 多个 provider 同时冷却 → 降 30%；
    4. 队列水位低（queued < cap）→ 有多少挖多少，不空转；
    5. 同机构扎堆（ratio >= 阈值）→ 降 20% 减少重复探测。
    """
    base = _clamp(int(user_concurrency or 0), 1, int(global_max or 1))
    cap = base
    reasons: list[str] = []

    if llm_under_cooldown:
        cap = max(1, math.ceil(cap * 0.5))
        reasons.append("LLM 全池冷却，并发减半")

    if llm_provider_cooldowns >= PROVIDER_COOLDOWN_THRESHOLD:
        cap = max(1, math.ceil(cap * 0.7))
        reasons.append(f"{llm_provider_cooldowns} 个 LLM 端点冷却，并发降低")

    if 0 <= queued_count < cap:
        cap = max(1, queued_count)
        reasons.append(f"队列水位低（queued={queued_count}），按需并发")

    if same_org_ratio >= SAME_ORG_RATIO_THRESHOLD:
        cap = max(1, math.ceil(cap * 0.8))
        reasons.append(f"同机构目标扎堆（{same_org_ratio:.0%}），并发降低")

    return cap, reasons


def same_org_ratio(rows: list[tuple[str, str]]) -> float:
    """给定 [(school, org), ...] 列表，返回同机构扎堆占比（0~1）。

    教育看 school、企业看 org，取两者各自最大占比。空列表返回 0。
    """
    if not rows:
        return 0.0
    from collections import Counter
    schools = Counter(s for s, _ in rows if s)
    orgs = Counter(o for _, o in rows if o)
    max_share = 0.0
    for counter in (schools, orgs):
        if counter:
            share = max(counter.values()) / len(rows)
            max_share = max(max_share, share)
    return max_share