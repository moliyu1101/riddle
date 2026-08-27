"""情报命中统计面板测试：_aggregate_hit_stats 纯函数聚合逻辑。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.intel import _aggregate_hit_stats  # noqa: E402
from app.db.models import Intel  # noqa: E402


def _mk_intel(id, kind, match_key, hit_count, summary="", last_seen=None):
    it = Intel(id=id, kind=kind, match_key=match_key, hit_count=hit_count, summary=summary)
    if last_seen is not None:
        it.last_seen = last_seen
    return it


class AggregateHitStatsTest(unittest.TestCase):
    def test_empty_input(self):
        out = _aggregate_hit_stats([], [])
        self.assertEqual(out["reuse_dist"], {"once": 0, "few": 0, "many": 0})
        self.assertEqual(out["top_reused"], [])
        self.assertEqual(out["top_sources"], [])
        self.assertEqual(out["by_kind"]["cred"]["total"], 0)

    def test_kind_counts_and_verified(self):
        rows = [
            ("cred", "verified", 3, "a.edu.cn"),
            ("cred", "likely", 1, "b.edu.cn"),
            ("fingerprint", "verified", 2, "c.edu.cn"),
        ]
        out = _aggregate_hit_stats(rows, [])
        self.assertEqual(out["by_kind"]["cred"]["total"], 2)
        self.assertEqual(out["by_kind"]["cred"]["verified"], 1)
        self.assertEqual(out["by_kind"]["cred"]["reused"], 1)
        self.assertEqual(out["by_kind"]["cred"]["avg_hit"], 2.0)
        self.assertEqual(out["by_kind"]["fingerprint"]["total"], 1)
        self.assertEqual(out["by_kind"]["fingerprint"]["verified"], 1)

    def test_reuse_distribution(self):
        rows = [
            ("cred", "likely", 1, ""),   # once
            ("cred", "likely", 3, ""),   # few
            ("cred", "likely", 9, ""),   # many
            ("cred", "likely", 5, ""),   # few (边界 <=5)
            ("cred", "likely", 6, ""),   # many (边界 >5)
        ]
        out = _aggregate_hit_stats(rows, [])
        self.assertEqual(out["reuse_dist"], {"once": 1, "few": 2, "many": 2})

    def test_avg_hit_rounding(self):
        rows = [("cred", "likely", 1, ""), ("cred", "likely", 2, "")]
        out = _aggregate_hit_stats(rows, [])
        self.assertEqual(out["by_kind"]["cred"]["avg_hit"], 1.5)

    def test_unknown_kind_grouped_other(self):
        rows = [("weird", "likely", 1, "")]
        out = _aggregate_hit_stats(rows, [])
        self.assertIn("other", out["by_kind"])
        self.assertEqual(out["by_kind"]["other"]["total"], 1)

    def test_top_sources_sorted_and_capped(self):
        rows = [(f"cred", "likely", 1, f"host{i}.edu.cn") for i in range(12)]
        out = _aggregate_hit_stats(rows, [])
        self.assertEqual(len(out["top_sources"]), 8)
        self.assertEqual(out["top_sources"][0]["count"], 1)
        self.assertEqual(out["top_sources"][0]["host"], "host0.edu.cn")

    def test_top_reused_serialization(self):
        items = [
            _mk_intel("i1", "lesson", "edu_jwgl", 7, summary="已出洞打法 [越权] 教务成绩"),
            _mk_intel("i2", "cred", "a.edu.cn", 3),
        ]
        out = _aggregate_hit_stats([], items)
        self.assertEqual(len(out["top_reused"]), 2)
        first = out["top_reused"][0]
        self.assertEqual(first["id"], "i1")
        self.assertEqual(first["kind"], "lesson")
        self.assertEqual(first["match_key"], "edu_jwgl")
        self.assertEqual(first["hit_count"], 7)
        self.assertEqual(first["summary"], "已出洞打法 [越权] 教务成绩")
        self.assertIn("last_seen", first)

    def test_all_kinds_present_in_by_kind(self):
        out = _aggregate_hit_stats([], [])
        for k in ("cred", "fingerprint", "endpoint", "profile", "lesson"):
            self.assertIn(k, out["by_kind"])
            self.assertEqual(out["by_kind"][k]["total"], 0)


if __name__ == "__main__":
    unittest.main()
