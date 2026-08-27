"""模型商预设 / temperature 智能推荐 / 端点池调度预览。"""
import asyncio
import unittest

from app.api.settings import (
    PoolSchedulePreviewRequest,
    ProviderHealthCheckRequest,
    TemperatureRecommendRequest,
    llm_provider_presets,
    pool_schedule_preview_endpoint,
    provider_health_check,
    temperature_recommend_endpoint,
)
from app.llm.presets import (
    LLM_PROVIDER_PRESETS,
    pool_schedule_preview,
    provider_preset,
    recommend_temperature,
)


class ProviderPresetsTest(unittest.TestCase):
    def test_presets_nonempty(self):
        self.assertGreaterEqual(len(LLM_PROVIDER_PRESETS), 7)

    def test_preset_fields(self):
        for p in LLM_PROVIDER_PRESETS:
            self.assertIn("id", p)
            self.assertIn("name", p)
            self.assertIn("base_url", p)
            self.assertIn("protocol", p)
            self.assertIn("recommended", p)

    def test_custom_preset_empty(self):
        custom = provider_preset("custom")
        self.assertIsNotNone(custom)
        self.assertEqual(custom["base_url"], "")

    def test_unknown_preset_none(self):
        self.assertIsNone(provider_preset("nope"))


class RecommendTemperatureTest(unittest.TestCase):
    def test_reasoning_model_low(self):
        res = recommend_temperature("deepseek-reasoner", "hunt")
        self.assertEqual(res["temperature"], 0.0)
        self.assertIn("推理模型", res["reason"])

    def test_coder_model(self):
        res = recommend_temperature("deepseek-coder", "hunt")
        self.assertEqual(res["temperature"], 0.1)
        self.assertIn("代码模型", res["reason"])

    def test_light_chat_model(self):
        res = recommend_temperature("gpt-4o-mini", "hunt")
        self.assertEqual(res["temperature"], 0.3)

    def test_general_model(self):
        res = recommend_temperature("gpt-4o", "hunt")
        self.assertEqual(res["temperature"], 0.6)

    def test_unknown_model_default(self):
        res = recommend_temperature("some-random-model", "hunt")
        self.assertEqual(res["temperature"], 0.3)

    def test_report_role_raises(self):
        res = recommend_temperature("gpt-4o", "report")
        self.assertEqual(res["temperature"], 0.8)

    def test_clamp(self):
        # 推理模型 + report 仍 clamp 到 >= 0
        res = recommend_temperature("deepseek-reasoner", "report")
        self.assertGreaterEqual(res["temperature"], 0.0)
        self.assertLessEqual(res["temperature"], 2.0)


class PoolSchedulePreviewTest(unittest.TestCase):
    def test_distribution(self):
        res = pool_schedule_preview([
            {"name": "A", "weight": 3, "enabled": True},
            {"name": "B", "weight": 1, "enabled": True},
        ])
        self.assertEqual(res["total_weight"], 4)
        shares = {d["name"]: d["share"] for d in res["distribution"]}
        self.assertEqual(shares["A"], 0.75)
        self.assertEqual(shares["B"], 0.25)
        self.assertIn("weighted", res["strategy"])

    def test_disabled_excluded(self):
        res = pool_schedule_preview([
            {"name": "A", "weight": 1, "enabled": True},
            {"name": "B", "weight": 1, "enabled": False},
        ])
        self.assertEqual(res["total_weight"], 1)
        shares = {d["name"]: d["share"] for d in res["distribution"]}
        self.assertEqual(shares["A"], 1.0)
        self.assertEqual(shares["B"], 0.0)

    def test_empty(self):
        res = pool_schedule_preview([])
        self.assertEqual(res["total_weight"], 0)
        self.assertEqual(res["distribution"], [])


class EndpointsTest(unittest.TestCase):
    def _call_presets(self):
        return asyncio.run(llm_provider_presets())

    def _call_temp(self, model, role="hunt"):
        return asyncio.run(temperature_recommend_endpoint(
            TemperatureRecommendRequest(model=model, role=role)
        ))

    def _call_pool(self, providers):
        return asyncio.run(pool_schedule_preview_endpoint(
            PoolSchedulePreviewRequest(providers=providers)
        ))

    def test_presets_endpoint(self):
        res = self._call_presets()
        self.assertGreaterEqual(len(res["presets"]), 7)

    def test_temp_endpoint(self):
        res = self._call_temp("deepseek-reasoner")
        self.assertEqual(res["temperature"], 0.0)
        self.assertIn("reason", res)

    def test_pool_endpoint(self):
        res = self._call_pool([
            {"name": "A", "weight": 2, "enabled": True},
            {"name": "B", "weight": 2, "enabled": True},
        ])
        self.assertEqual(res["total_weight"], 4)
        self.assertEqual(len(res["distribution"]), 2)

    def test_health_check_unknown(self):
        res = asyncio.run(provider_health_check(ProviderHealthCheckRequest(providers=[
            {"name": "A", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat", "api_key": "sk-x", "protocol": "auto"},
        ])))
        self.assertEqual(len(res["providers"]), 1)
        self.assertEqual(res["providers"][0]["health"]["status"], "unknown")
        self.assertTrue(res["providers"][0]["health_ref"])

    def test_health_check_empty(self):
        res = asyncio.run(provider_health_check(ProviderHealthCheckRequest(providers=[])))
        self.assertEqual(res["providers"], [])


if __name__ == "__main__":
    unittest.main()
