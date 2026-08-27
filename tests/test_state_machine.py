"""业务状态机引导：多步业务流绕过测试手法识别与渲染。"""
from __future__ import annotations

import unittest

from app.agents.state_machine import detect_flow_patterns, render_state_machine_block


class StateMachineTests(unittest.TestCase):
    def test_approval_flow_detected(self):
        pats = detect_flow_patterns(business_id="oa", title="行政审批流程系统")
        ids = [p.flow_id for p in pats]
        self.assertIn("approval_chain", ids)

    def test_payment_flow_detected(self):
        pats = detect_flow_patterns(business_id="pay", title="校园支付平台", description="订单支付")
        ids = [p.flow_id for p in pats]
        self.assertIn("payment_order", ids)

    def test_booking_flow_detected(self):
        pats = detect_flow_patterns(business_id="jwc", title="选课系统", description="抢课")
        ids = [p.flow_id for p in pats]
        self.assertIn("booking_selection", ids)

    def test_no_match_returns_empty_block(self):
        block = render_state_machine_block(title="某静态展示页")
        self.assertEqual(block, "")

    def test_render_includes_techniques(self):
        block = render_state_machine_block(business_id="pay", title="支付平台", description="订单 金额 退款")
        self.assertIn("业务状态机引导", block)
        self.assertIn("金额/数量篡改", block)
        self.assertIn("支付状态跳变", block)

    def test_business_id_boosts_relevance(self):
        # 无业务 ID 但标题命中，也应识别
        pats = detect_flow_patterns(title="审批流程系统")
        self.assertTrue(any(p.flow_id == "approval_chain" for p in pats))

    def test_password_reset_detected(self):
        pats = detect_flow_patterns(title="密码重置功能")
        self.assertTrue(any(p.flow_id == "password_reset" for p in pats))

    def test_max_patterns_limits_output(self):
        block = render_state_machine_block(
            business_id="pay",
            title="支付平台 审批 选课 注册 密码重置 积分",
            description="订单 金额 退款 预约 报名 优惠券",
            max_patterns=2,
        )
        # 模式标题行形如 "- 支付/订单："（带中文冒号），只应出现 2 个
        titles = [ln for ln in block.splitlines() if ln.startswith("- ") and "：" in ln]
        self.assertLessEqual(len(titles), 2)


if __name__ == "__main__":
    unittest.main()
