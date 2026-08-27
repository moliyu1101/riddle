"""经验知识引导测试：lessons 库按目标信号匹配并注入，无命中时为空。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.lessons import match_lessons, render_lessons_block  # noqa: E402


class MatchLessonsTest(unittest.TestCase):
    def test_spa_matches_api_lessons(self):
        hits = match_lessons(["/route/vue", "vue", "webpack"], limit=5)
        ids = [h["id"] for h in hits]
        self.assertIn("spa_api", ids)

    def test_login_matches_weakpwd_and_idor(self):
        hits = match_lessons(["/route/login", "登录", "弱口令"], limit=5)
        ids = [h["id"] for h in hits]
        self.assertIn("captcha_weakpwd", ids)
        self.assertIn("post_login_idor", ids)

    def test_payment_matches_state_flow(self):
        hits = match_lessons(["缴费", "审批", "订单"], limit=3)
        self.assertTrue(any(h["id"] == "state_flow" for h in hits))

    def test_no_match_returns_empty(self):
        hits = match_lessons(["随便", "无关", "static"], limit=3)
        self.assertEqual(hits, [])

    def test_empty_signals(self):
        self.assertEqual(match_lessons([]), [])

    def test_limit_respected(self):
        hits = match_lessons(["登录", "上传", "导出", "api", "vue", "支付"], limit=2)
        self.assertLessEqual(len(hits), 2)

    def test_render_empty_when_no_match(self):
        self.assertEqual(render_lessons_block(["无关内容"]), "")

    def test_render_nonempty_on_match(self):
        block = render_lessons_block(["登录弱口令", "上传"])
        self.assertIn("经验引导", block)
        self.assertIn("弱口令", block)


if __name__ == "__main__":
    unittest.main()