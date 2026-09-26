"""work_dir 防碰撞：超过 60 字符的长 URL 目标截断后前缀可能相同，须以内容哈希区分。"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402


class WorkdirCollisionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="_wd_test_")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def test_long_urls_get_distinct_workdirs(self):
        a = "https://target.example.edu.cn/" + "a" * 100
        b = "https://target.example.edu.cn/" + "a" * 99 + "b"
        d1 = ToolExecutor(a, work_dir=self._tmp).work_dir
        d2 = ToolExecutor(b, work_dir=self._tmp).work_dir
        self.assertNotEqual(d1, d2)

    def test_short_target_keeps_legacy_name(self):
        d = ToolExecutor("https://x.example.com", work_dir=self._tmp).work_dir
        self.assertEqual(d.name, "https___x_example_com")


if __name__ == "__main__":
    unittest.main()
