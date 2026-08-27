"""差异化评分：大众洞识别 + 差异化打分 + 策略/审核参考块。"""
from __future__ import annotations

import unittest

from app.agents.diff_score import (
    diff_strategy_block,
    review_diff_note,
    score_differentiation,
)


class DiffScoreTests(unittest.TestCase):
    def test_common_sqli_on_known_system_is_common(self):
        ds = score_differentiation(
            vuln_type="sql_injection",
            title="某大学教务系统登录框SQL注入",
            description="登录接口存在SQL注入，报错特征明显",
            owner="某大学（正方教务）",
        )
        self.assertEqual(ds.tier, "common")
        self.assertLess(ds.score, 40)
        self.assertTrue(any("SQL注入" in r for r in ds.reasons))
        self.assertTrue(any("正方" in h for h in ds.common_hits))

    def test_business_logic_idor_is_differentiated(self):
        ds = score_differentiation(
            vuln_type="idor",
            title="选课接口水平越权可代他人选课",
            description="通过替换studentId可越权操作用户选课，状态真实变化",
            owner="某大学教务系统",
        )
        self.assertGreaterEqual(ds.tier, "differentiated")
        self.assertGreaterEqual(ds.score, 60)

    def test_reflected_xss_is_heavily_common(self):
        ds = score_differentiation(
            vuln_type="reflected_xss",
            title="搜索框反射型XSS",
            description="参数未过滤导致反射型XSS",
        )
        self.assertEqual(ds.tier, "common")
        self.assertLess(ds.score, 40)

    def test_weak_evidence_downgrades(self):
        ds = score_differentiation(
            vuln_type="unauthorized_access",
            title="后台接口未授权访问",
            description="接口存在未授权访问，仅返回200空响应，无实际数据",
        )
        self.assertIn("弱证据", " ".join(ds.reasons))
        self.assertLess(ds.score, 60)

    def test_strong_evidence_boosts(self):
        ds = score_differentiation(
            vuln_type="idor",
            title="学籍接口越权读取",
            description="越权读取他人学籍，含身份证号、密码哈希，批量导出成功",
            owner="某大学",
        )
        self.assertIn("强证据", " ".join(ds.reasons))
        self.assertGreaterEqual(ds.score, 60)

    def test_known_cve_is_common(self):
        ds = score_differentiation(
            vuln_type="rce",
            title="某系统存在CVE-2021-44228 Log4j漏洞",
            description="已知CVE，nuclei模板命中",
        )
        self.assertEqual(ds.tier, "common")
        self.assertLess(ds.score, 40)

    def test_strategy_block_mentions_differentiation(self):
        block = diff_strategy_block(business_id="jwc", business_label="教务系统")
        self.assertIn("差异化", block)
        self.assertIn("教务", block)
        self.assertIn("大众洞", block)

    def test_review_note_common_is_strict(self):
        ds = score_differentiation(
            vuln_type="sql_injection",
            title="登录框SQL注入",
            description="报错特征",
        )
        note = review_diff_note(ds)
        self.assertIn("大众洞", note)
        self.assertIn("验收从严", note)

    def test_review_note_rare_not_misjudged(self):
        ds = score_differentiation(
            vuln_type="business_logic",
            title="审批流状态机绕过",
            description="通过并发提交绕过审批状态机，实现越权审批，真实状态变化",
            owner="某OA系统",
        )
        note = review_diff_note(ds)
        self.assertIn("别因类型陌生误杀", note)

    def test_score_clamped(self):
        ds = score_differentiation(
            vuln_type="reflected_xss",
            title="反射型XSS self-xss 弱口令 用户名枚举 phpinfo",
            description="phpinfo泄露 目录列举 开放重定向 已知CVE-2021",
        )
        self.assertGreaterEqual(ds.score, 0)
        self.assertLessEqual(ds.score, 100)


if __name__ == "__main__":
    unittest.main()
