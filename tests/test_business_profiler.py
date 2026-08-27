"""业务上下文画像：识别业务类型并按业务逻辑引导 worker（差异化挖洞）。"""
from __future__ import annotations

import unittest

from app.agents.business_profiler import profile_business, render_business_block
from app.agents.playbook_router import route_target


class BusinessProfilerTests(unittest.TestCase):
    def test_jwc_identified(self):
        p = profile_business(title="某某大学教务管理系统", school="某某大学")
        self.assertIsNotNone(p)
        self.assertEqual(p.biz_id, "jwc")
        self.assertIn("选课", p.focus[0])
        self.assertIn("教务系统", p.label)

    def test_payment_identified(self):
        p = profile_business(title="校园统一缴费平台", org="某某大学")
        self.assertIsNotNone(p)
        self.assertEqual(p.biz_id, "payment")
        self.assertTrue(any("金额" in f for f in p.focus))

    def test_approval_identified(self):
        p = profile_business(title="行政审批流程系统", org="某某单位")
        self.assertIsNotNone(p)
        self.assertEqual(p.biz_id, "approval")
        self.assertTrue(any("审批节点" in f for f in p.focus))

    def test_oa_identified(self):
        p = profile_business(title="OA协同办公-审批中心", org="某某单位")
        self.assertIsNotNone(p)
        self.assertEqual(p.biz_id, "oa")

    def test_no_match_returns_none(self):
        p = profile_business(title="欢迎访问", url="https://example.com/")
        self.assertIsNone(p)

    def test_render_block_contains_focus(self):
        p = profile_business(title="后勤报修平台", school="某某大学")
        block = render_business_block(p)
        self.assertIn("业务画像", block)
        self.assertIn("报修", block)
        self.assertIn("工单", block)

    def test_render_none_is_empty(self):
        self.assertEqual(render_business_block(None), "")

    def test_priority_reason_can_trigger(self):
        p = profile_business(title="首页", priority_reason="教务系统 选课 成绩")
        self.assertIsNotNone(p)
        self.assertEqual(p.biz_id, "jwc")

    def test_route_target_weights_business(self):
        # 有业务画像时，业务/IDOR 路线应被加权选中，而非回退到 generic_admin_api。
        plan = route_target(
            url="https://jw.example.edu.cn/",
            title="教务系统",
            business_id="jwc",
        )
        self.assertIn(plan.route_id, ("upload_business_idor", "api_authorization"))
        self.assertTrue(any("biz:jwc" in t for t in plan.tags))

    def test_route_target_without_business_stays_default(self):
        plan = route_target(url="https://example.edu.cn/", title="欢迎访问")
        self.assertEqual(plan.route_id, "generic_admin_api")


if __name__ == "__main__":
    unittest.main()
