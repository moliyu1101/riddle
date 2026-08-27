"""覆盖通杀闭环：最小验证入队 + 人工选择数量批量入队。

规则：
- _enqueue_killsweep_minimal：只入队 1 个最低单位站点证明通杀（优先 verified_url，
  否则取 affected_table 里第一个 verified 站点）；跳过 origin 自身、无效/敏感主机、重复 host。
- enqueue_killsweep_assets：人工选择数量，从 affected_table 的 verified 站点按序入队 count 个；
  已入队过的 host 自动跳过（Target 去重）。
"""
import unittest

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.models import Base, Killsweep, Target
from app.orchestrator import TaskRunner

ORIGIN = "https://https.test.school.edu.cn"
_ORIGIN_HOST = "https.test.school.edu.cn"


class TestKillsweepClosedLoop(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def _hosts(self, task_id: str) -> set:
        async with self.Session() as s:
            rows = (await s.execute(
                select(Target.host).where(Target.task_id == task_id)
            )).scalars().all()
        return set(rows)

    @staticmethod
    def _runner():
        # 用一个不触发 __init__ 的空壳实例绑定目标方法，仅供单测调用。
        runner = object.__new__(TaskRunner)
        runner._enqueue_killsweep_target = TaskRunner._enqueue_killsweep_target.__get__(runner, TaskRunner)
        return runner

    async def test_minimal_only_one_verified_skips_origin_candidate_dup(self):
        table = [
            {"url": "http://a.school.edu.cn", "status": "verified"},
            {"url": "http://b.school.edu.cn", "status": "verified"},
            {"url": "http://c.school.edu.cn", "status": "candidate"},  # 不入队
            {"url": ORIGIN, "status": "verified"},                     # 源站自身，跳过
            {"url": "http://a.school.edu.cn", "status": "verified"},   # 重复 host，跳过
        ]
        async with self.Session() as s:
            count = await self._runner()._enqueue_killsweep_minimal(
                s, "task_t1", table, "", ORIGIN)
            await s.commit()
        # 通杀闭环：只入队 1 个最低单位站点证明通杀
        self.assertEqual(count, 1)
        self.assertEqual(await self._hosts("task_t1"), {"a.school.edu.cn"})

    async def test_minimal_prefers_verified_url(self):
        table = [
            {"url": "http://a.school.edu.cn", "status": "verified"},
            {"url": "http://b.school.edu.cn", "status": "verified"},
        ]
        async with self.Session() as s:
            count = await self._runner()._enqueue_killsweep_minimal(
                s, "task_t1", table, "http://b.school.edu.cn", ORIGIN)
            await s.commit()
        self.assertEqual(count, 1)
        self.assertEqual(await self._hosts("task_t1"), {"b.school.edu.cn"})

    async def test_minimal_empty_table_returns_zero(self):
        async with self.Session() as s:
            count = await self._runner()._enqueue_killsweep_minimal(
                s, "task_t2", [], "", ORIGIN)
        self.assertEqual(count, 0)
        self.assertEqual(await self._hosts("task_t2"), set())

    async def test_enqueue_assets_manual_count(self):
        table = [
            {"url": "http://a.school.edu.cn", "status": "verified"},
            {"url": "http://b.school.edu.cn", "status": "verified"},
            {"url": "http://c.school.edu.cn", "status": "candidate"},  # 不入队
            {"url": "http://d.school.edu.cn", "status": "verified"},
        ]
        async with self.Session() as s:
            k = Killsweep(
                task_id="task_t3", origin_finding_id="f1", product_key="p1",
                product_name="测试系统", vuln_type="SQL注入", vuln_summary="测试洞",
                status="done", is_killsweep=True, verified=True,
                verified_url="http://origin.school.edu.cn", affected_table=table,
            )
            s.add(k)
            await s.commit()
            await s.refresh(k)
            result = await self._runner().enqueue_killsweep_assets(s, "task_t3", k.id, 2)
            await s.commit()
        self.assertEqual(result["enqueued"], 2)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(await self._hosts("task_t3"), {"a.school.edu.cn", "b.school.edu.cn"})

    async def test_enqueue_assets_skips_already_enqueued(self):
        table = [
            {"url": "http://a.school.edu.cn", "status": "verified"},
            {"url": "http://b.school.edu.cn", "status": "verified"},
        ]
        async with self.Session() as s:
            k = Killsweep(
                task_id="task_t4", origin_finding_id="f2", product_key="p2",
                product_name="测试系统", vuln_type="XSS", vuln_summary="测试洞",
                status="done", is_killsweep=True, verified=True,
                verified_url="http://origin.school.edu.cn", affected_table=table,
            )
            s.add(k)
            await s.commit()
            await s.refresh(k)
            # 先入队 1 个，再入队 2 个：a 已入队应跳过，只新增 b
            first = await self._runner().enqueue_killsweep_assets(s, "task_t4", k.id, 1)
            second = await self._runner().enqueue_killsweep_assets(s, "task_t4", k.id, 2)
            await s.commit()
        self.assertEqual(first["enqueued"], 1)
        self.assertEqual(second["enqueued"], 1)
        self.assertEqual(second["skipped"], 1)
        self.assertEqual(await self._hosts("task_t4"), {"a.school.edu.cn", "b.school.edu.cn"})

    async def test_enqueue_assets_not_killsweep_raises(self):
        async with self.Session() as s:
            k = Killsweep(
                task_id="task_t5", origin_finding_id="f3", product_key="p3",
                product_name="测试系统", vuln_type="XSS", vuln_summary="测试洞",
                status="done", is_killsweep=False, affected_table=[],
            )
            s.add(k)
            await s.commit()
            await s.refresh(k)
            with self.assertRaises(ValueError):
                await self._runner().enqueue_killsweep_assets(s, "task_t5", k.id, 3)


if __name__ == "__main__":
    unittest.main()
