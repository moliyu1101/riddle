"""业务逻辑测试模板（阶段二）测试。

验证：模板选择（专属/通用兜底）、渲染结构、模板完整性（每个测试点字段非空）。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.biz_test_template import (  # noqa: E402
    _BUSINESS_TEMPLATES,
    _GENERIC_TEMPLATE,
    render_biz_test_block,
    select_template,
)


class SelectTemplateTest(unittest.TestCase):
    def test_known_biz_returns_specific(self):
        tmpl = select_template("jwc")
        self.assertEqual(tmpl.biz_id, "jwc")
        self.assertNotEqual(tmpl.biz_id, "generic")

    def test_unknown_biz_falls_back_to_generic(self):
        tmpl = select_template("")
        self.assertEqual(tmpl.biz_id, "generic")
        tmpl2 = select_template("unknown_biz")
        self.assertEqual(tmpl2.biz_id, "generic")

    def test_all_business_templates_registered(self):
        # 每个业务模板都有非空测试点
        for biz_id, tmpl in _BUSINESS_TEMPLATES.items():
            self.assertGreater(len(tmpl.points), 0, f"{biz_id} 无测试点")
            self.assertTrue(tmpl.label, f"{biz_id} 无标签")


class RenderBlockTest(unittest.TestCase):
    def test_render_specific_business(self):
        block = render_biz_test_block(business_id="payment", business_label="支付缴费")
        self.assertIn("支付缴费", block)
        self.assertIn("业务逻辑测试模板", block)
        self.assertIn("实锤标准", block)
        self.assertIn("金额篡改", block)

    def test_render_generic_fallback(self):
        block = render_biz_test_block()
        self.assertIn("通用业务逻辑", block)
        self.assertIn("对象 ID 遍历", block)
        self.assertIn("水平越权", block)

    def test_render_max_points_cap(self):
        block = render_biz_test_block(business_id="oa", max_points=2)
        # OA 有 4 个测试点，max_points=2 只渲染 2 条
        self.assertEqual(block.count("步骤："), 2)

    def test_every_point_has_steps_and_proof(self):
        for tmpl in list(_BUSINESS_TEMPLATES.values()) + [_GENERIC_TEMPLATE]:
            for p in tmpl.points:
                self.assertTrue(p.feature, f"{tmpl.biz_id} 有 feature 为空")
                self.assertTrue(p.vuln_type, f"{tmpl.biz_id}.{p.feature} 无 vuln_type")
                self.assertGreater(len(p.steps), 0, f"{tmpl.biz_id}.{p.feature} 无步骤")
                self.assertTrue(p.proof, f"{tmpl.biz_id}.{p.feature} 无实锤标准")


class TemplateCoverageTest(unittest.TestCase):
    def test_business_profiler_ids_covered(self):
        # business_profiler 的 18 类业务都应覆盖到（避免识别出业务却无模板）
        from app.agents.business_profiler import _BUSINESS_PROFILES

        for biz in _BUSINESS_PROFILES:
            self.assertIn(
                biz.biz_id, _BUSINESS_TEMPLATES,
                f"业务 {biz.biz_id}({biz.label}) 缺少测试模板",
            )


if __name__ == "__main__":
    unittest.main()
