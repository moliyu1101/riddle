"""任务级禁止操作：用户规则里的"不能做 X"要硬约束执行层，而非只靠 prompt 提示。

覆盖：
- parse_forbidden_ops：从规则文本解析禁止操作（需同时命中禁止前缀 + 操作关键词）
- check_task_forbidden：命中禁止操作抛 CommandBlocked（硬拦，不弹确认）
- ToolExecutor 集成：run_shell / http_request 注入 src_rules 后硬拦截
- prompts：append_task_src_rules 把禁止操作以硬约束块写入 system prompt
- /parse-forbidden-ops 接口：前端规则区实时硬约束预览的数据源
"""
import asyncio
import tempfile
import unittest

from app.agents.prompts import append_task_src_rules
from app.api.dto import ParseForbiddenOpsRequest
from app.api.tasks import parse_forbidden_ops_endpoint
from app.tools.executor import ToolExecutor
from app.tools.guard import (
    CommandBlocked,
    check_task_forbidden,
    parse_forbidden_ops,
)


class ParseForbiddenOpsTest(unittest.TestCase):
    def test_empty_rules(self):
        self.assertEqual(parse_forbidden_ops(""), [])
        self.assertEqual(parse_forbidden_ops("   \n  "), [])

    def test_chinese_forbid_delete_and_dump(self):
        banned = parse_forbidden_ops("不能做删除、脱库等操作")
        self.assertIn("db_delete", banned)
        self.assertIn("db_dump", banned)

    def test_forbid_cache_clear(self):
        self.assertIn("cache_clear", parse_forbidden_ops("禁止清缓存"))

    def test_forbid_brute_force(self):
        self.assertIn("brute_force", parse_forbidden_ops("严禁爆破"))

    def test_forbid_dos(self):
        self.assertIn("dos", parse_forbidden_ops("不要压测"))

    def test_forbid_webshell(self):
        self.assertIn("webshell", parse_forbidden_ops("不允许落 webshell"))

    def test_forbid_cred_change(self):
        self.assertIn("cred_change", parse_forbidden_ops("不得改密码"))

    def test_english_no_delete(self):
        self.assertIn("db_delete", parse_forbidden_ops("no delete operations"))

    def test_case_insensitive_dump(self):
        self.assertIn("db_dump", parse_forbidden_ops("No DUMP allowed"))

    def test_review_semantics_not_execution(self):
        # 审核语义（不收/忽略）不含禁止前缀，不应误判成执行禁止
        self.assertEqual(parse_forbidden_ops("不收弱口令"), [])
        self.assertEqual(parse_forbidden_ops("不收删除类漏洞"), [])
        self.assertEqual(parse_forbidden_ops("忽略信息泄露"), [])

    def test_ordered_and_deduped(self):
        banned = parse_forbidden_ops("不能删除，也不能脱库，更不能删库")
        self.assertEqual(banned.count("db_delete"), 1)
        self.assertEqual(banned.count("db_dump"), 1)


class CheckTaskForbiddenTest(unittest.TestCase):
    def test_no_forbidden_ops_passes(self):
        check_task_forbidden("sqlmap -u http://x/ --dump-all", [])

    def test_hits_delete_from(self):
        with self.assertRaises(CommandBlocked):
            check_task_forbidden("mysql -e 'DELETE FROM users'", ["db_delete"])

    def test_hits_sqlmap_dump(self):
        with self.assertRaises(CommandBlocked):
            check_task_forbidden("sqlmap -u http://x/ --dump-all", ["db_dump"])

    def test_hits_flushall(self):
        with self.assertRaises(CommandBlocked):
            check_task_forbidden("redis-cli FLUSHALL", ["cache_clear"])

    def test_hits_hydra(self):
        with self.assertRaises(CommandBlocked):
            check_task_forbidden("hydra -l admin -P rockyou.txt ssh", ["brute_force"])

    def test_benign_command_passes(self):
        check_task_forbidden("curl -s http://example.edu.cn/", ["db_delete", "db_dump"])

    def test_unbanned_op_passes(self):
        # 只禁止了脱库，没禁止删除 → DELETE 放行
        check_task_forbidden("mysql -e 'DELETE FROM users'", ["db_dump"])


class ExecutorIntegrationTest(unittest.TestCase):
    def _executor(self, src_rules: str) -> ToolExecutor:
        return ToolExecutor(
            "example.edu.cn",
            work_dir=tempfile.mkdtemp(),
            src_rules=src_rules,
        )

    def test_run_shell_blocks_forbidden(self):
        ex = self._executor("不能做删除、脱库等操作")
        res = ex.run_shell("mysql -e 'DELETE FROM users'")
        self.assertTrue(res.get("blocked"))
        self.assertIn("任务规则禁止", res.get("error", ""))

    def test_run_shell_blocks_sqlmap_dump(self):
        ex = self._executor("禁止脱库")
        res = ex.run_shell("sqlmap -u http://x/ --dump-all")
        self.assertTrue(res.get("blocked"))

    def test_run_shell_allows_benign(self):
        ex = self._executor("不能做删除、脱库等操作")
        res = ex.run_shell("echo hello")
        # 只断言未被规则拦截（Windows 本地 subprocess 执行有环境差异，不检查 rc）
        self.assertFalse(res.get("blocked"))

    def test_run_shell_no_rules_passes(self):
        ex = self._executor("")
        res = ex.run_shell("echo hi")
        self.assertFalse(res.get("blocked"))

    def test_http_request_blocks_forbidden(self):
        ex = self._executor("不能做删除、脱库等操作")
        res = ex.http_request(
            "POST", "https://example.edu.cn/query",
            data="q=1; DELETE FROM users",
        )
        self.assertTrue(res.get("blocked"))
        self.assertIn("任务规则禁止", res.get("error", ""))

    def test_http_request_blocks_dump_in_url(self):
        ex = self._executor("禁止脱库")
        res = ex.http_request(
            "GET", "https://example.edu.cn/sqlmap?cmd=--dump-all",
        )
        self.assertTrue(res.get("blocked"))

    def test_http_request_allows_normal(self):
        ex = self._executor("不能做删除、脱库等操作")
        res = ex.http_request("GET", "https://example.edu.cn/")
        # 正常请求不应被规则拦截（网络失败不算 blocked）
        self.assertFalse(res.get("blocked"))

    def test_http_request_no_rules_passes(self):
        ex = self._executor("")
        res = ex.http_request("GET", "https://example.edu.cn/")
        self.assertFalse(res.get("blocked"))


class PromptHardBlockTest(unittest.TestCase):
    def test_forbidden_block_appended(self):
        out = append_task_src_rules("base prompt", "不能做删除、脱库等操作")
        self.assertIn("本任务硬性禁止执行的操作", out)
        self.assertIn("脱库/拖库/删库", out)
        self.assertIn("删除数据", out)

    def test_no_forbidden_no_block(self):
        out = append_task_src_rules("base prompt", "不收弱口令")
        self.assertNotIn("本任务硬性禁止执行的操作", out)

    def test_empty_rules_unchanged(self):
        self.assertEqual(append_task_src_rules("base prompt", ""), "base prompt")


class ParseForbiddenOpsEndpointTest(unittest.TestCase):
    def _call(self, text: str):
        return asyncio.run(parse_forbidden_ops_endpoint(ParseForbiddenOpsRequest(text=text)))

    def test_empty(self):
        res = self._call("")
        self.assertEqual(res.count, 0)
        self.assertEqual(res.forbidden, [])
        self.assertEqual(res.labels, "")

    def test_review_semantics_only(self):
        # 纯审核语义（不收/忽略）不触发执行禁止
        res = self._call("不收弱口令；忽略信息泄露")
        self.assertEqual(res.count, 0)

    def test_forbid_dump_and_delete(self):
        res = self._call("不能做删除、脱库等操作")
        ids = [f["id"] for f in res.forbidden]
        self.assertIn("db_dump", ids)
        self.assertIn("db_delete", ids)
        self.assertEqual(res.count, 2)
        self.assertIn("脱库/拖库/删库", res.labels)
        self.assertIn("删除数据", res.labels)

    def test_all_eight_categories(self):
        res = self._call(
            "禁止脱库、删库；禁止删除数据；禁止写入篡改；禁止清缓存；"
            "禁止改密、重置凭证；禁止爆破；禁止压测、轰炸；禁止落 webshell、后门"
        )
        self.assertEqual(res.count, 8)
        labels = {f["label"] for f in res.forbidden}
        self.assertIn("脱库/拖库/删库", labels)
        self.assertIn("删除数据", labels)
        self.assertIn("写入/篡改数据", labels)
        self.assertIn("清缓存", labels)
        self.assertIn("改密/重置凭证", labels)
        self.assertIn("爆破/暴力破解", labels)
        self.assertIn("压测/DoS/轰炸", labels)
        self.assertIn("落 webshell/后门", labels)

    def test_labels_join(self):
        res = self._call("禁止脱库，禁止爆破")
        self.assertEqual(res.labels, "脱库/拖库/删库、爆破/暴力破解")


if __name__ == "__main__":
    unittest.main()
