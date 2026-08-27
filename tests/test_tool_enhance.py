"""工具增强测试：run_shell 终端化 / path_probe / injection_probe。

覆盖：
- run_shell 终端化：cd/export 状态持久化、纯状态命令不执行、历史去重提示、大输出摘要
- path_probe：路径字典爆破 + 备份/源码泄露探测（命中特征校验、预算分配、限量）
- injection_probe：CORS/SSRF/命令注入/SSTI/XXE 五类探针（信号判定、限量、参数校验）
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.executor import ToolExecutor  # noqa: E402
from app.tools.probe_tools import injection_probe  # noqa: E402


def _resp(status=200, body="", headers=None):
    return {"ok": True, "status_code": status, "body": body,
            "response_headers": headers or {}, "title": ""}


class FakeInjExecutor:
    """injection_probe 的 mock：按调用序号返回预设响应，并记录调用参数。"""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def http_request(self, url, method="GET", headers=None, data=None, timeout=20, **kw):
        self.calls.append({"url": url, "method": method, "headers": headers, "data": data})
        if self.responses:
            return self.responses.pop(0)
        return _resp()


class FakePathExecutor(ToolExecutor):
    """path_probe 的 mock：覆盖 http_request 返回预设响应，并记录调用 URL。"""

    def __init__(self, responses=None, src_rules=""):
        super().__init__("example.edu.cn", work_dir=tempfile.mkdtemp(), src_rules=src_rules)
        self._responses = list(responses or [])
        self.calls = []

    def http_request(self, url, method="GET", timeout=20, **kw):
        self.calls.append(url)
        if self._responses:
            return self._responses.pop(0)
        return _resp(404)


# ---- run_shell 终端化 ----
class ApplyShellStateTest(unittest.TestCase):
    def _ex(self):
        return ToolExecutor("example.edu.cn", work_dir=tempfile.mkdtemp())

    def test_cd_updates_cwd(self):
        ex = self._ex()
        sub = ex.work_dir / "subdir"
        sub.mkdir()
        cmd, hint = ex._apply_shell_state("cd subdir")
        self.assertEqual(cmd, "")
        self.assertIn("[cwd]", hint)
        self.assertEqual(ex._shell_cwd, sub.resolve())

    def test_cd_with_rest_returns_remainder(self):
        ex = self._ex()
        sub = ex.work_dir / "subdir"
        sub.mkdir()
        cmd, hint = ex._apply_shell_state("cd subdir && echo hi")
        self.assertEqual(cmd, "echo hi")
        self.assertIn("[cwd]", hint)
        self.assertEqual(ex._shell_cwd, sub.resolve())

    def test_export_updates_env(self):
        ex = self._ex()
        cmd, hint = ex._apply_shell_state("export FOO=bar")
        self.assertEqual(cmd, "")
        self.assertIn("[env] FOO=bar", hint)
        self.assertEqual(ex._shell_env.get("FOO"), "bar")

    def test_regular_passthrough(self):
        ex = self._ex()
        cmd, hint = ex._apply_shell_state("curl -s http://x/")
        self.assertEqual(cmd, "curl -s http://x/")
        self.assertEqual(hint, "")

    def test_cd_nonexistent_keeps_cwd(self):
        ex = self._ex()
        before = ex._shell_cwd
        cmd, hint = ex._apply_shell_state("cd /no/such/dir/xyz")
        self.assertIn("目录不存在", hint)
        self.assertEqual(ex._shell_cwd, before)


class SummarizeOutputTest(unittest.TestCase):
    def test_extracts_signal_lines(self):
        text = "\n".join([
            "line one",
            "ERROR: connection refused",
            "line two",
            "token=abc123",
            "line three",
        ])
        digest = ToolExecutor._summarize_output(text)
        self.assertIn("ERROR: connection refused", digest)
        self.assertIn("token=abc123", digest)
        self.assertNotIn("line one", digest)

    def test_empty_returns_empty(self):
        self.assertEqual(ToolExecutor._summarize_output(""), "")

    def test_no_signal_returns_empty(self):
        self.assertEqual(ToolExecutor._summarize_output("普通输出\n没有关键信号\n"), "")


class RunShellTerminalTest(unittest.TestCase):
    def _ex(self, src_rules=""):
        return ToolExecutor("example.edu.cn", work_dir=tempfile.mkdtemp(), src_rules=src_rules)

    def test_pure_state_command_no_exec(self):
        ex = self._ex()
        sub = ex.work_dir / "subdir"
        sub.mkdir()
        res = ex.run_shell("cd subdir")
        self.assertTrue(res.get("ok"))
        self.assertIn("[cwd]", res.get("output", ""))
        self.assertEqual(ex._shell_cwd, sub.resolve())

    def test_history_dedup_hint(self):
        ex = self._ex()
        res1 = ex.run_shell("echo hi")
        self.assertNotIn("此前已执行过", res1.get("output", ""))
        res2 = ex.run_shell("echo hi")
        self.assertIn("此前已执行过 2 次", res2.get("output", ""))

    def test_persistent_cwd(self):
        ex = self._ex()
        sub = ex.work_dir / "subdir"
        sub.mkdir()
        ex.run_shell("cd subdir")
        res = ex.run_shell("cd")  # cmd 无参 cd 打印当前目录
        self.assertTrue(res.get("ok"))
        self.assertIn("subdir", res.get("output", ""))

    def test_persistent_env(self):
        ex = self._ex()
        res = ex.run_shell("export FOO=bar")
        self.assertTrue(res.get("ok"))
        self.assertIn("[env] FOO=bar", res.get("output", ""))
        self.assertEqual(ex._shell_env.get("FOO"), "bar")

    def test_blocked_by_forbidden(self):
        ex = self._ex(src_rules="不能删除数据")
        res = ex.run_shell("mysql -e 'DELETE FROM users'")
        self.assertTrue(res.get("blocked"))


# ---- path_probe ----
class PathProbeTest(unittest.TestCase):
    def test_arg_error_empty_url(self):
        out = FakePathExecutor().path_probe(url="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_origin_building(self):
        ex = FakePathExecutor([_resp(404)])
        out = ex.path_probe(url="example.edu.cn", max_paths=1)
        self.assertTrue(out["ok"])
        self.assertEqual(out["base"], "https://example.edu.cn")

    def test_collects_hits_and_backup(self):
        # max_paths=3 → 1 常规 + 2 备份（.git/config 带特征命中）
        ex = FakePathExecutor([
            _resp(200, "admin page"),
            _resp(200, "[core]\nrepositoryformatversion = 0"),
            _resp(404),
        ])
        out = ex.path_probe(url="https://example.edu.cn", max_paths=3)
        self.assertTrue(out["ok"])
        self.assertEqual(out["probed"], 3)
        self.assertEqual(out["hit_count"], 2)
        self.assertTrue(out["hits"][0]["backup"])  # 备份命中排前
        self.assertEqual(out["hits"][0]["path"], "/.git/config")

    def test_backup_without_marker_skipped(self):
        ex = FakePathExecutor([
            _resp(200, "admin page"),
            _resp(200, "just a normal page"),
            _resp(404),
        ])
        out = ex.path_probe(url="https://example.edu.cn", max_paths=3)
        self.assertEqual(out["hit_count"], 1)
        self.assertFalse(out["hits"][0]["backup"])

    def test_include_backup_false(self):
        # max_paths=5 → 3 常规路径，无备份路径
        ex = FakePathExecutor([_resp(200, "a"), _resp(200, "b"), _resp(200, "c")])
        out = ex.path_probe(url="https://example.edu.cn", max_paths=5, include_backup=False)
        self.assertEqual(out["probed"], 3)
        self.assertEqual(out["hit_count"], 3)
        self.assertTrue(all(not h["backup"] for h in out["hits"]))

    def test_max_paths_cap(self):
        ex = FakePathExecutor()
        out = ex.path_probe(url="https://example.edu.cn", max_paths=999)
        self.assertLessEqual(out["probed"], 80)

    def test_blocked_by_forbidden(self):
        ex = FakePathExecutor(src_rules="不能爆破")
        out = ex.path_probe(url="https://hydra.example.edu.cn")
        self.assertTrue(out.get("blocked"))


# ---- injection_probe ----
class InjectionProbeTest(unittest.TestCase):
    def test_arg_error_empty_url(self):
        out = injection_probe(FakeInjExecutor(), url="", param_name="id")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_arg_error_empty_param(self):
        out = injection_probe(FakeInjExecutor(), url="https://x/api?id=1", param_name="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "arg_error")

    def test_cors_reflection_signal(self):
        ex = FakeInjExecutor([_resp(200, "page", {"access-control-allow-origin": "https://evil.example.com"})])
        out = injection_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["cors"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("CORS 配置错误" in s for s in out["signals"]))

    def test_cors_no_reflection_negative(self):
        ex = FakeInjExecutor([_resp(200, "page", {"access-control-allow-origin": "https://example.com"})])
        out = injection_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["cors"])
        self.assertEqual(out["verdict"], "negative")
        self.assertEqual(out["signals"], [])

    def test_ssrf_signal(self):
        ex = FakeInjExecutor([_resp(200, "ami-id: ami-123 instance-id: i-abc"), _resp(200, "page")])
        out = injection_probe(ex, url="https://x/api?url=", param_name="url", probe_types=["ssrf"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("SSRF 信号" in s for s in out["signals"]))

    def test_cmdi_signal(self):
        ex = FakeInjExecutor([_resp(200, "RIDDLE_CMDI_7f3a9"), _resp(200, "p"), _resp(200, "p"), _resp(200, "p")])
        out = injection_probe(ex, url="https://x/api?cmd=", param_name="cmd", probe_types=["cmdi"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("命令注入信号" in s for s in out["signals"]))

    def test_ssti_signal(self):
        ex = FakeInjExecutor([_resp(200, "result: 49"), _resp(200, "p"), _resp(200, "p"), _resp(200, "p")])
        out = injection_probe(ex, url="https://x/api?name=", param_name="name", probe_types=["ssti"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("SSTI 信号" in s for s in out["signals"]))

    def test_xxe_signal(self):
        ex = FakeInjExecutor([_resp(200, "root:x:0:0:root:/root:/bin/bash")])
        out = injection_probe(ex, url="https://x/api", param_name="xml", probe_types=["xxe"])
        self.assertEqual(out["verdict"], "likely")
        self.assertTrue(any("XXE 信号" in s for s in out["signals"]))

    def test_negative_verdict(self):
        ex = FakeInjExecutor([_resp(200, "page", {"access-control-allow-origin": "https://example.com"})])
        out = injection_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["cors"])
        self.assertEqual(out["verdict"], "negative")
        self.assertIn("未观察到", out["guidance"])

    def test_request_cap(self):
        ex = FakeInjExecutor([_resp(200, "page")] * 20)
        out = injection_probe(ex, url="https://x/api?user=1", param_name="user")
        self.assertLessEqual(len(ex.calls), 12)

    def test_invalid_type_fallback(self):
        ex = FakeInjExecutor([_resp(200, "page")] * 20)
        out = injection_probe(ex, url="https://x/api?user=1", param_name="user", probe_types=["weird"])
        self.assertEqual(out["probe_types"], ["cors", "ssrf", "cmdi", "ssti", "xxe"])


if __name__ == "__main__":
    unittest.main()
