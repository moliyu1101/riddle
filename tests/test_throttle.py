"""多目标并发智能节流：纯逻辑测试（无 IO、确定性）。"""
from __future__ import annotations

import pytest

from app.agents.throttle import (
    PROVIDER_COOLDOWN_THRESHOLD,
    SAME_ORG_RATIO_THRESHOLD,
    compute_effective_cap,
    same_org_ratio,
)


class TestComputeEffectiveCap:
    def test_baseline_no_downgrade(self):
        cap, reasons = compute_effective_cap(8, 16, queued_count=100)
        assert cap == 8
        assert reasons == []

    def test_global_max_caps_user(self):
        cap, _ = compute_effective_cap(32, 16, queued_count=100)
        assert cap == 16

    def test_llm_pool_cooldown_halves(self):
        cap, reasons = compute_effective_cap(8, 16, queued_count=100, llm_under_cooldown=True)
        assert cap == 4
        assert any("冷却" in r for r in reasons)

    def test_llm_pool_cooldown_floor_one(self):
        cap, _ = compute_effective_cap(1, 16, queued_count=100, llm_under_cooldown=True)
        assert cap == 1

    def test_provider_cooldowns_reduce(self):
        cap, reasons = compute_effective_cap(10, 16, queued_count=100,
                                             llm_provider_cooldowns=PROVIDER_COOLDOWN_THRESHOLD)
        assert cap == 7  # ceil(10*0.7)
        assert any("端点冷却" in r for r in reasons)

    def test_provider_cooldowns_below_threshold_no_effect(self):
        cap, reasons = compute_effective_cap(10, 16, queued_count=100,
                                             llm_provider_cooldowns=PROVIDER_COOLDOWN_THRESHOLD - 1)
        assert cap == 10
        assert reasons == []

    def test_low_queue_scale_to_need(self):
        cap, reasons = compute_effective_cap(8, 16, queued_count=3)
        assert cap == 3
        assert any("队列水位低" in r for r in reasons)

    def test_low_queue_never_zero(self):
        cap, _ = compute_effective_cap(8, 16, queued_count=0)
        assert cap == 1

    def test_same_org_cluster_reduces(self):
        cap, reasons = compute_effective_cap(10, 16, queued_count=100,
                                             same_org_ratio=SAME_ORG_RATIO_THRESHOLD)
        assert cap == 8  # ceil(10*0.8)
        assert any("扎堆" in r for r in reasons)

    def test_same_org_below_threshold_no_effect(self):
        cap, reasons = compute_effective_cap(10, 16, queued_count=100,
                                             same_org_ratio=SAME_ORG_RATIO_THRESHOLD - 0.01)
        assert cap == 10
        assert reasons == []

    def test_combined_factors_take_minimum(self):
        # 全池冷却(减半 8->4) + provider 冷却(4*0.7=2.8->3) + 扎堆(3*0.8=2.4->3)
        cap, reasons = compute_effective_cap(8, 16, queued_count=100,
                                             llm_under_cooldown=True,
                                             llm_provider_cooldowns=PROVIDER_COOLDOWN_THRESHOLD,
                                             same_org_ratio=1.0)
        assert cap == 3
        assert len(reasons) == 3

    def test_combined_with_low_queue(self):
        # 队列水位低是最后一道：先算其它因子，再按队列取 min。
        cap, _ = compute_effective_cap(8, 16, queued_count=2,
                                       llm_under_cooldown=True,
                                       same_org_ratio=1.0)
        assert cap == 2

    def test_never_below_one_with_all_factors(self):
        cap, _ = compute_effective_cap(1, 1, queued_count=0,
                                       llm_under_cooldown=True,
                                       llm_provider_cooldowns=99,
                                       same_org_ratio=1.0)
        assert cap == 1

    def test_zero_user_concurrency_defaults_one(self):
        cap, _ = compute_effective_cap(0, 16, queued_count=100)
        assert cap == 1

    def test_zero_global_max_defaults_one(self):
        cap, _ = compute_effective_cap(8, 0, queued_count=100)
        assert cap == 1

    def test_negative_queued_ignored(self):
        cap, reasons = compute_effective_cap(8, 16, queued_count=-5)
        assert cap == 8
        assert reasons == []


class TestSameOrgRatio:
    def test_empty_returns_zero(self):
        assert same_org_ratio([]) == 0.0

    def test_school_cluster(self):
        rows = [("A大学", ""), ("A大学", ""), ("B学院", ""), ("", "")]
        assert same_org_ratio(rows) == 0.5

    def test_org_cluster(self):
        rows = [("", "某集团"), ("", "某集团"), ("", "其他公司")]
        assert same_org_ratio(rows) == pytest.approx(2 / 3)

    def test_school_beats_org(self):
        # school 扎堆 0.6，org 分散 0.2，取最大 0.6。
        rows = [("A大学", "X"), ("A大学", "Y"), ("A大学", "Z"), ("B学院", "X"), ("C学院", "X")]
        assert same_org_ratio(rows) == 0.6

    def test_all_distinct(self):
        rows = [("A", "1"), ("B", "2"), ("C", "3")]
        assert same_org_ratio(rows) == pytest.approx(1 / 3)

    def test_none_values_treated_empty(self):
        rows = [(None, None), ("A", None), (None, "B")]
        assert same_org_ratio(rows) == pytest.approx(1 / 3)
