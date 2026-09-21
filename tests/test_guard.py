import unittest

from app.tools.guard import CommandBlocked, NeedsConfirm, check_command, check_http_request


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
