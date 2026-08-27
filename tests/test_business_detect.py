"""http_request 自动业务识别测试：从页面 HTML 识别业务系统并动态注入引导。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402


def _html(title: str, meta: str = "", body_text: str = "") -> str:
    meta_tag = f'<meta name="description" content="{meta}">' if meta else ""
    return (
        "<!DOCTYPE html><html><head><title>"
        + title
        + "</title>"
        + meta_tag
        + "</head><body><div>"
        + body_text
        + "</div></body></html>"
    )


class BusinessDetectTest(unittest.TestCase):
    def setUp(self):
        self.ex = ToolExecutor("https://jwxt.example.edu.cn", work_dir=str(ROOT / "data" / "_tmp_biz_test"))

    def test_detect_jwc_from_title(self):
        biz = self.ex._detect_business_from_html(
            "https://jwxt.example.edu.cn/",
            _html("XX大学教务管理系统 - 选课中心", "选课、成绩查询、课表", "欢迎使用教务系统"),
        )
        self.assertIsNotNone(biz)
        self.assertEqual(biz["biz_id"], "jwc")
        self.assertGreaterEqual(biz["confidence"], 0.5)
        self.assertIn("业务画像", biz["block"])

    def test_detect_oa_from_visible_text(self):
        # 标题无关键词，但可见文本含业务关键词也能识别
        biz = self.ex._detect_business_from_html(
            "https://oa.example.edu.cn/",
            _html("统一门户", "", "办公自动化系统，公文管理、考勤、日程、通讯录"),
        )
        self.assertIsNotNone(biz)
        self.assertEqual(biz["biz_id"], "oa")

    def test_detect_pay_from_meta(self):
        biz = self.ex._detect_business_from_html(
            "https://pay.example.edu.cn/",
            _html("网上缴费平台", "在线支付、缴费、订单", ""),
        )
        self.assertIsNotNone(biz)
        self.assertEqual(biz["biz_id"], "payment")

    def test_no_business_returns_none(self):
        biz = self.ex._detect_business_from_html(
            "https://plain.example.edu.cn/",
            _html("欢迎", "", "hello world"),
        )
        self.assertIsNone(biz)

    def test_cache_prevents_reanalysis(self):
        first = self.ex._detect_business_from_html(
            "https://jwxt.example.edu.cn/",
            _html("XX大学教务管理系统", "", "教务"),
        )
        # 同 host 二次调用即使内容不同也走缓存
        second = self.ex._detect_business_from_html(
            "https://jwxt.example.edu.cn/",
            _html("完全无关页面", "", "noise"),
        )
        self.assertEqual(first["biz_id"], second["biz_id"])
        self.assertEqual(first["biz_id"], "jwc")

    def test_low_confidence_filtered(self):
        # 只有极弱信号（如单个泛词）不应误判
        biz = self.ex._detect_business_from_html(
            "https://weak.example.edu.cn/",
            _html("测试", "", "系统"),
        )
        self.assertIsNone(biz)


if __name__ == "__main__":
    unittest.main()
