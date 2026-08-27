"""目标优先级评分：差异化维度 + 四档位划分。"""
from __future__ import annotations

import unittest

from app.agents.scorer import score_target


class ScorerDiffTierTests(unittest.TestCase):
    def test_business_logic_target_is_rare(self):
        sc, reason = score_target(
            "https://pay.example.edu.cn",
            title="学生缴费管理系统",
            body="<title>缴费管理后台</title> 支付 订单 审批 报名",
            probe_endpoints=False,
        )
        self.assertGreaterEqual(sc, 10)
        self.assertTrue(reason.startswith("[稀有]"))

    def test_authz_target_gets_diff_bonus(self):
        sc, reason = score_target(
            "https://admin.example.edu.cn",
            title="用户权限管理后台",
            body="账号管理 用户管理 权限管理 角色",
            probe_endpoints=False,
        )
        self.assertGreaterEqual(sc, 6)
        self.assertIn("差异化:authz", reason)

    def test_generic_framework_target_is_downgraded(self):
        sc, reason = score_target(
            "https://blog.example.com",
            title="wordpress 博客",
            body="wp-content 搜索 查询",
            probe_endpoints=False,
        )
        self.assertLess(sc, 3)
        self.assertIn("大众洞:generic_framework", reason)

    def test_pure_frontend_is_common(self):
        sc, reason = score_target(
            "https://www.example.edu.cn",
            title="学校官网首页",
            body="<title>学校官网</title> 新闻网 门户 概况 简介",
            probe_endpoints=False,
        )
        self.assertLess(sc, 3)
        self.assertTrue(reason.startswith("[大众]"))

    def test_auth_gateway_is_common(self):
        sc, reason = score_target(
            "https://sso.example.edu.cn",
            title="统一身份认证",
            body="<input type='password'> /api/login /api/user",
            probe_endpoints=False,
        )
        self.assertLess(sc, 3)
        self.assertTrue(reason.startswith("[大众]"))

    def test_login_api_target_is_normal(self):
        sc, reason = score_target(
            "https://lib.example.edu.cn",
            title="图书馆检索系统",
            body="<input type='password'> \"/api/search\" \"/api/book\"",
            probe_endpoints=False,
        )
        self.assertGreaterEqual(sc, 3)
        self.assertLess(sc, 6)
        self.assertTrue(reason.startswith("[普通]"))

    def test_state_machine_target_gets_bonus(self):
        sc, reason = score_target(
            "https://flow.example.edu.cn",
            title="审批流程系统",
            body="流程 审批流 状态变更 审核",
            probe_endpoints=False,
        )
        self.assertGreaterEqual(sc, 6)
        self.assertIn("差异化:state_machine", reason)

    def test_enterprise_mode_still_works(self):
        sc, reason = score_target(
            "https://erp.example.com",
            title="企业 ERP 管理后台",
            body="CRM 订单 支付 审批 合同",
            probe_endpoints=False,
            src_type="enterprise",
        )
        self.assertGreaterEqual(sc, 6)
        self.assertIn("enterprise_admin", reason) or self.assertIn("enterprise_core_business", reason)

    def test_reason_prefix_is_tier(self):
        sc, reason = score_target(
            "https://x.example.edu.cn",
            title="普通测试站",
            body="",
            probe_endpoints=False,
        )
        self.assertRegex(reason, r"^\[(稀有|差异化|普通|大众)\]")


if __name__ == "__main__":
    unittest.main()
