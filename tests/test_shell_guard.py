"""低价值 shell 防护回归：姊妹域误拦修复后，对当前目标（含端口/子域）的合法验证不再被拦。"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str, worker_id: str = "w1"):
    events = []
    w = Worker(
        target,
        llm=Mock(),
        on_event=lambda kind, data: events.append((kind, data)),
        src_type="edusrc",
        worker_id=worker_id,
    )
    return w, events


class LowValueShellGuardTest(unittest.TestCase):
    def test_login_brute_on_current_target_with_port(self):
        """对带端口目标的弱口令验证（当前目标）不应被姊妹域规则误拦。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        cmd = (
            'for p in admin123 123456 Hzcu@123; do '
            'curl -s -m 10 -X POST http://admin-api.hzcu.edu.cn/login '
            '-d "password=$p"; done'
        )
        self.assertEqual(w._low_value_shell_reason(cmd, rnd=12), "")

    def test_subdomain_request_is_not_sibling(self):
        """目标为父域时，请求其子域不算偏离（同机构）。"""
        w, _ = _make_worker("http://hzcu.edu.cn")
        cmd = 'curl -s http://admin-api.hzcu.edu.cn/api/info'
        self.assertEqual(w._low_value_shell_reason(cmd, rnd=8), "")

    def test_unrelated_school_still_blocked(self):
        """请求与目标无关的其他学校域，仍被拦（真实偏离）。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        cmd = 'curl -s http://www.other.edu.cn/api -H "x: $p"'
        # 单个请求也走姊妹域规则（rnd>=6）
        self.assertNotEqual(w._low_value_shell_reason(cmd, rnd=8), "")

    def test_bulk_subdomain_enumeration_still_blocked(self):
        """明确的批量姊妹域枚举（for sub in）仍被拦。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        cmd = 'for sub in a b c d; do curl -s http://$sub.hzcu.edu.cn; done'
        self.assertNotEqual(w._low_value_shell_reason(cmd, rnd=10), "")

    def test_early_rounds_not_blocked(self):
        """早期（rnd<6）不做姊妹域/批量限制，避免误伤探索阶段。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        cmd = 'curl -s http://www.other.edu.cn/api'
        self.assertEqual(w._low_value_shell_reason(cmd, rnd=3), "")

    def test_same_interface_variant_enum_allowed(self):
        """同一接口的方法/参数变体枚举（docfileinfo/download、getFile…共享前缀）不被当作泛目录扫描。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        paths = " ".join(f'"docfileinfo/{m}?fileid=8788996"' for m in
                         ("download", "getFile", "readFile", "showFile", "downLoad",
                          "getFileById", "readFileById", "downloadFile", "getFileInfo",
                          "viewFile", "openFile", "fileDownLoad"))
        cmd = f"for p in {paths}; do curl -s http://admin-api.hzcu.edu.cn/$p; done"
        self.assertEqual(w._low_value_shell_reason(cmd, rnd=10), "")

    def test_generic_path_enum_still_blocked(self):
        """前缀各异的泛路径猜测（/admin /api /config /backup…）仍被拦。"""
        w, _ = _make_worker("http://admin-api.hzcu.edu.cn:8082")
        paths = " ".join(f'"/{d}"' for d in
                         ("admin", "api", "config", "backup", "bak", "old", "test",
                          "upload", "uploads", "static", "files", "download"))
        cmd = f"for p in {paths}; do curl -s http://admin-api.hzcu.edu.cn$p; done"
        self.assertNotEqual(w._low_value_shell_reason(cmd, rnd=10), "")


if __name__ == "__main__":
    unittest.main()
