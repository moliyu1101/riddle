import unittest

from app.tools.guard import CommandBlocked, NeedsConfirm, check_command, check_http_request, check_rm_cwd


class GuardDestructiveTest(unittest.TestCase):
    def test_allows_idor_delete(self):
        check_http_request("DELETE", "https://example.edu.cn/api/ticket/delete?id=88")

    def test_allows_src_test_delete_from(self):
        check_command("mysql -e \"DELETE FROM comments WHERE note='SRC_TEST_abc'\"")

    def test_drop_pauses_for_reflection(self):
        with self.assertRaises(NeedsConfirm):
            check_command("mysql -e 'DROP TABLE users'", enterprise=False)

    def test_drop_in_http_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "POST", "https://example.edu.cn/query",
                data="q=1; DROP TABLE users",
            )

    def test_cache_clear_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request("POST", "https://example.edu.cn/admin/cache/clear")

    def test_sqlmap_dump_all_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_command("sqlmap -u http://x/ --dump-all")

    def test_overwrite_download_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "PUT",
                "https://example.edu.cn/download/notice.pdf",
                data="tampered",
            )


class RmCwdGuardTest(unittest.TestCase):
    """rm 语义级检查：堵「cd 切 cwd + 相对路径」绕过文本黑名单的形态。"""

    def _blocked(self, cmd: str, cwd: str):
        with self.assertRaises(CommandBlocked):
            check_rm_cwd(cmd, cwd)

    def test_cd_then_relative_rm_blocked(self):
        """`cd /app && rm -rf data`：文本层不含 /app，按切换后的 cwd 解析必须拦。"""
        self._blocked("rm -rf data", "/app")
        self._blocked("rm -rf ./data", "/app")

    def test_long_option_rm_blocked(self):
        """长选项 --recursive 不匹配旧的短选项正则，语义解析必须拦。"""
        self._blocked("rm --recursive --force /app", "/work/t1")
        self._blocked("rm --recursive --force /app", "/")

    def test_dot_and_dotdot_blocked(self):
        self._blocked("rm -rf .", "/app")
        self._blocked("rm -rf ..", "/app/data")
        self._blocked("rm -rf ../..", "/work/t1/sub")

    def test_work_root_level_blocked_but_subtree_allowed(self):
        """/work 根级删除拦；/work/<目标> 子树是 worker 工作区，允许清理。"""
        self._blocked("rm -rf /work", "/tmp")
        self._blocked("rm -rf /work/*", "/tmp")
        check_rm_cwd("rm -rf /work/http_x/notes", "/tmp")
        check_rm_cwd("rm -rf *", "/work/http_x")

    def test_glob_in_protected_cwd_blocked(self):
        self._blocked("rm -rf *", "/app")
        self._blocked("rm -rf /app/*", "/tmp")
        self._blocked("rm -rf data*", "/app")

    def test_home_variants_blocked(self):
        self._blocked("rm -rf ~", "/work/t1")
        self._blocked('rm -rf "$HOME"', "/work/t1")
        self._blocked("rm -rf /root", "/tmp")

    def test_harmless_targets_pass(self):
        check_rm_cwd("rm -rf /tmp/x", "/app")
        check_rm_cwd("rm -rf /work/t1/cache", "/")
        check_rm_cwd("rm data.log", "/work/t1")

    def test_non_leading_rm_not_matched(self):
        """grep/echo 参数文本里的 rm 串不误伤。"""
        check_rm_cwd("grep 'rm -rf /app' access.log", "/work/t1")
        check_rm_cwd("echo rm -rf /app", "/work/t1")

    def test_sh_c_inner_recursed(self):
        self._blocked('echo ok && bash -c "rm -rf data"', "/app")
        self._blocked("sh -c 'rm -rf /app'", "/tmp")

    def test_dd_and_separator_segments(self):
        """分号/管道切分后的段首 rm 也检查。"""
        self._blocked("echo hi; rm -rf /app", "/tmp")
        self._blocked("curl -s http://x | tee f && rm -rf /app/data", "/tmp")

    def test_confirm_without_reason_still_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "POST", "https://example.edu.cn/admin/cache/clear",
                confirm_destructive=True, confirm_reason="",
            )

    def test_confirm_with_reason_allows(self):
        check_http_request(
            "POST", "https://example.edu.cn/admin/cache/clear",
            confirm_destructive=True,
            confirm_reason="只证明接口存在，随后不真正清",
        )

    def test_self_destruct_still_hard_blocks(self):
        with self.assertRaises(CommandBlocked):
            check_command("rm -rf --no-preserve-root /", confirm_destructive=True, confirm_reason="no")

    def test_rm_app_subtree_hard_blocks(self):
        for cmd in (
            "rm -rf /app",
            "rm -rf /app/data",
            "rm -rf /app/data/riddle.db",
            "rm -rf /app/*",
            "rm -rf '/app/data'",
            "rm -fr /app",
            "rm -rf -- /app",
            "cd /tmp && rm -rf /app/data",
        ):
            with self.assertRaises(CommandBlocked, msg=cmd):
                check_command(cmd, confirm_destructive=True, confirm_reason="no")

    def test_rm_work_root_hard_blocks_but_subdir_allowed(self):
        with self.assertRaises(CommandBlocked):
            check_command("rm -rf /work", confirm_destructive=True, confirm_reason="no")
        with self.assertRaises(CommandBlocked):
            check_command("rm -rf /work/", confirm_destructive=True, confirm_reason="no")
        # worker 清理自己目标目录下的临时文件属于合法操作
        check_command("rm -rf /work/target/evidence/tmp_download.zip")
        check_command("rm -rf /tmp/sqlmap_output")

    def test_rm_home_variants_hard_blocks(self):
        for cmd in (
            "rm -rf ~",
            "rm -rf ~/*",
            "rm -rf \"$HOME\"",
            "rm -rf \"$HOME\"/*",
            "rm -rf ${HOME}/*",
            "rm -rf /root",
        ):
            with self.assertRaises(CommandBlocked, msg=cmd):
                check_command(cmd, confirm_destructive=True, confirm_reason="no")
        # 只删家目录下具体子目录（如 nuclei 模板缓存）不拦
        check_command("rm -rf ~/.cache/nuclei")

    def test_platform_files_overwrite_hard_blocks(self):
        with self.assertRaises(CommandBlocked):
            check_command("dd if=/dev/zero of=/app/data/riddle.db bs=1M count=100")
        with self.assertRaises(CommandBlocked):
            check_command("find /app -name '*.db' -delete")
        with self.assertRaises(CommandBlocked):
            check_command("find /work -type f -delete")
        with self.assertRaises(CommandBlocked):
            check_command("find /app/data -exec rm -f {} ;")
        with self.assertRaises(CommandBlocked):
            check_command("chmod -R 000 /app/data")

    def test_attack_commands_still_allowed(self):
        # 攻击类命令不受影响（守卫只拦自毁）
        check_command("rm -rf /tmp/x")
        check_command("nmap -sV --script=http-title example.edu.cn")
        check_command("sqlmap -u http://example.edu.cn/ --risk 2 --batch")
        check_command("curl -s http://example.edu.cn/ -o /work/target/page.html")
        check_command("wget -r -l 1 http://example.edu.cn/ -P /work/target")

    def test_allows_src_test_upload(self):
        check_http_request(
            "POST",
            "https://example.edu.cn/uploads/SRC_TEST_probe.txt",
            data="ok",
        )

    def test_allows_boolean_sqli(self):
        check_http_request(
            "GET",
            "https://example.edu.cn/item?id=1 AND 1=1",
        )


if __name__ == "__main__":
    unittest.main()
