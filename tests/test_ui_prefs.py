"""外观偏好 normalize_ui 新字段（uiScale / motion）回归测试。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.ui_prefs import DEFAULT_UI, normalize_ui, public_ui
from app.api.dto import SettingsUpdateRequest


class NormalizeUiScaleTests(unittest.TestCase):
    def test_defaults_when_missing(self):
        ui = normalize_ui({})
        self.assertEqual(ui["uiScale"], DEFAULT_UI["uiScale"])
        self.assertEqual(ui["motion"], DEFAULT_UI["motion"])

    def test_clamps_out_of_range(self):
        ui = normalize_ui({"uiScale": 0.5, "motion": "off"})
        self.assertEqual(ui["uiScale"], 0.85)  # 下限
        ui = normalize_ui({"uiScale": 2})
        self.assertEqual(ui["uiScale"], 1.15)  # 上限
        self.assertEqual(ui["motion"], "on")   # 默认

    def test_invalid_falls_back(self):
        ui = normalize_ui({"uiScale": "abc", "motion": 123})
        self.assertEqual(ui["uiScale"], DEFAULT_UI["uiScale"])
        self.assertEqual(ui["motion"], "on")

    def test_round_trip(self):
        ui = normalize_ui({"uiScale": 1.075, "motion": "off"})
        again = normalize_ui(ui)
        self.assertEqual(again["uiScale"], 1.075)
        self.assertEqual(again["motion"], "off")

    def test_legacy_snake_case_alias(self):
        ui = normalize_ui({"ui_scale": 0.925})
        self.assertEqual(ui["uiScale"], 0.925)


class HueFallbackTests(unittest.TestCase):
    def test_missing_hues_use_own_defaults(self):
        ui = normalize_ui({})
        self.assertEqual(ui["accentHue"], 330)
        self.assertEqual(ui["accent2Hue"], 195)
        self.assertEqual(ui["bgHue"], 295)

    def test_legacy_row_without_new_fields_keeps_neon_defaults(self):
        ui = normalize_ui({"theme": "dark", "accentHue": 330, "saved": True})
        self.assertEqual(ui["accent2Hue"], 195)
        self.assertEqual(ui["bgHue"], 295)
        self.assertEqual(ui["glow"], 1.0)


class UiDtoRoundTripTests(unittest.TestCase):
    """PUT /api/settings 经 UiSettingsDTO 白名单，新字段缺失会被静默丢弃——防回归。"""

    def test_dto_keeps_all_appearance_fields(self):
        body = SettingsUpdateRequest.model_validate({
            "ui": {
                "theme": "dark",
                "accentHue": 285,
                "accent2Hue": 195,
                "bgHue": 300,
                "glow": 1.4,
                "uiScale": 1.075,
                "motion": "off",
                "wallpaperKind": "none",
            },
        })
        ui = body.model_dump(exclude_unset=True)["ui"]
        self.assertEqual(ui["accent2Hue"], 195)
        self.assertEqual(ui["bgHue"], 300)
        self.assertEqual(ui["glow"], 1.4)
        self.assertEqual(ui["uiScale"], 1.075)
        self.assertEqual(ui["motion"], "off")


class PublicUiPassthroughTests(unittest.TestCase):
    def test_public_ui_includes_new_fields(self):
        pub = public_ui({"uiScale": 0.925, "motion": "off"})
        self.assertEqual(pub["uiScale"], 0.925)
        self.assertEqual(pub["motion"], "off")


if __name__ == "__main__":
    unittest.main()
