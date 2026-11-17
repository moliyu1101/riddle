"""融合层数据库闭环：配置写入即时生效 → 双图重建 → 流量导入/绑定 → 公文 docx。

用独立临时 SQLite + dependency_overrides + httpx ASGITransport 在**同一个事件循环**
里跑完整链路：绕开 TestClient 的跨线程 loop 与 app.main lifespan 的 signal 注册，
同时不碰开发者真实库，也不残留 settings_service / security 的全局态。
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import security
from app.api import fusion
from app.db.models import (
    Base, Finding, FusionGoal, Target, Task, TaskEvent,
)
from app.fusion import config, traffic_ledger
from app import settings_service


class FusionEndToEndTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="_fusion_e2e_")
        self.work = Path(self.tmp.name)
        self.engine = create_async_engine(
            f"sqlite+aiosqlite:///{self.work / 'e2e.db'}", future=True
        )
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.Session = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

        async def _override_session():
            async with self.Session() as session:
                yield session

        self.app = FastAPI()
        self.app.include_router(fusion.router)
        self.app.dependency_overrides[fusion.get_session] = _override_session
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        )
        # update_settings → refresh_cache 会改全局配置缓存与 DB 令牌；测完必须还原
        self._cache_snapshot = dict(settings_service._cache)
        self._token_snapshot = dict(security._db_tokens)
        await self._seed()

    async def asyncTearDown(self):
        settings_service._cache = self._cache_snapshot
        security._db_tokens.clear()
        security._db_tokens.update(self._token_snapshot)
        await self.client.aclose()
        await self.engine.dispose()
        self.tmp.cleanup()

    async def _seed(self):
        async with self.Session() as s:
            s.add(Task(id="T-FUSION", name="融合闭环测试", status="running",
                       manual_targets=["https://a.example.edu.cn/admin"]))
            s.add(Target(id="TG-1", task_id="T-FUSION",
                         url="https://a.example.edu.cn/admin?id=1", host="a.example.edu.cn",
                         ip="93.184.216.34", title="管理后台", status="done"))
            s.add(Finding(
                id="F-1", task_id="T-FUSION", target_id="TG-1", worker_id="w1",
                vuln_type="sqli", title="SQL 注入可读取管理数据", severity_claimed="high",
                target_url="https://a.example.edu.cn/admin?id=1", owner="某归属单位",
                description="查询参数未过滤，可拼接条件读取越权数据。",
                affected_scope="管理后台查询接口", poc="curl -s 'https://a.example.edu.cn/admin?id=1'",
                steps=[{"desc": "构造 payload", "poc": "id=1' OR 1=1--"}],
                raw_response="HTTP/1.1 200 OK", evidence={"status_code": 200},
            ))
            s.add(FusionGoal(task_id="T-FUSION", goal_key="g1",
                             title="证明 SQL 注入 可读取数据",
                             criteria="返回 HTTP/1.1 200 OK 且响应包含管理字段",
                             kind="existence", status="open"))
            s.add(TaskEvent(task_id="T-FUSION", kind="finding_submitted", message="提交 SQL 注入"))
            await s.commit()

    async def test_full_pipeline(self):
        # 1) 前端保存配置：白名单收敛写入 DB overlay，worker/executor 立刻读到新值
        r = await self.client.put("/api/fusion/config", json={"config": {
            "traffic_enabled": True, "graphs_enabled": True, "report_enabled": True,
            "intel_lookback_days": 14, "nvd_api_key": "should-be-dropped",
        }})
        self.assertEqual(r.status_code, 200, r.text)
        saved = r.json()["saved"]
        self.assertTrue(saved["traffic_enabled"])
        self.assertEqual(saved["intel_lookback_days"], 14)
        self.assertNotIn("nvd_api_key", saved)
        self.assertTrue(config.load_config().traffic_enabled, "DB 写入后无需重启即刻生效")

        cfg = (await self.client.get("/api/fusion/config")).json()
        self.assertEqual(cfg["source"], "db")
        self.assertEqual(cfg["overlay"]["intel_lookback_days"], 14)

        status_resp = await self.client.get("/api/fusion/status")
        self.assertEqual(status_resp.status_code, 200, status_resp.text)
        status = status_resp.json()
        self.assertEqual(status["goal_count"], 1)
        self.assertGreaterEqual(len(status["modules"]), 8)

        # 2) executor 写下的 JSONL → 导入台账（按 sha256+url 幂等）
        traffic_dir = self.work / "traffic"
        traffic_ledger.capture_sync(
            traffic_dir,
            {"ok": True, "url": "https://a.example.edu.cn/admin?id=1", "status_code": 200,
             "final_method": "GET", "raw_request": "GET /admin?id=1 HTTP/1.1",
             "raw_response": "HTTP/1.1 200 OK", "body": "page-a"},
            "https://a.example.edu.cn/admin?id=1", "GET", "example.edu.cn",
        )
        traffic_ledger.capture_sync(
            traffic_dir,
            {"ok": True, "url": "https://a.example.edu.cn/admin?id=1", "status_code": 403,
             "final_method": "GET", "raw_request": "GET /admin HTTP/1.1",
             "raw_response": "HTTP/1.1 403 Forbidden", "body": "denied"},
            "https://a.example.edu.cn/admin", "GET", "example.edu.cn",
        )
        # 重复行，导入时应被去重
        traffic_ledger.append_jsonl(traffic_dir, traffic_ledger.read_jsonl(traffic_dir)[0])

        imp = await self.client.post("/api/fusion/traffic/import", json={
            "task_id": "T-FUSION", "work_dir": str(traffic_dir),
        })
        self.assertEqual(imp.status_code, 200, imp.text)
        self.assertEqual(imp.json()["scanned_rows"], 3)
        self.assertEqual(imp.json()["unique_rows"], 2)
        self.assertEqual(imp.json()["imported"], 2)
        again = await self.client.post("/api/fusion/traffic/import", json={
            "task_id": "T-FUSION", "work_dir": str(traffic_dir),
        })
        self.assertEqual(again.json()["imported"], 0, "二次导入必须幂等")

        listed = (await self.client.get("/api/fusion/traffic/T-FUSION")).json()
        self.assertEqual(listed["count"], 2)
        self.assertEqual(len(listed["grouped"]["proof"]), 1)
        self.assertEqual(len(listed["grouped"]["baseline"]), 1)

        # 3) 绑定到 finding；不存在的 finding 必须明确 404
        tid = listed["items"][0]["id"]
        bound = await self.client.post("/api/fusion/traffic/bind", json={
            "finding_id": "F-1", "traffic_ids": [tid], "role": "verification",
        })
        self.assertEqual(bound.status_code, 200, bound.text)
        self.assertEqual(bound.json()["updated"], 1)
        after = (await self.client.get("/api/fusion/traffic/T-FUSION")).json()
        self.assertEqual(len(after["grouped"]["verification"]), 1)
        bad = await self.client.post("/api/fusion/traffic/bind", json={
            "finding_id": "NO-SUCH", "traffic_ids": [tid], "role": "proof",
        })
        self.assertEqual(bad.status_code, 404)

        # 4) 双图重建 / 读取 / 血缘回溯 / 覆盖度
        rebuilt = await self.client.post("/api/fusion/graphs/T-FUSION/rebuild")
        self.assertEqual(rebuilt.status_code, 200, rebuilt.text)
        self.assertGreater(rebuilt.json()["nodes"], 5)
        self.assertGreater(rebuilt.json()["coverage"]["ratio"], 0)
        graph = (await self.client.get("/api/fusion/graphs/T-FUSION")).json()
        self.assertEqual(len(graph["nodes"]), rebuilt.json()["nodes"])
        self.assertEqual(len(graph["edges"]), rebuilt.json()["edges"])
        root = next(n for n in graph["nodes"] if n["label"] == "example.edu.cn")
        chain = (await self.client.get(
            "/api/fusion/graphs/T-FUSION/lineage", params={"node_id": root["id"]}
        )).json()["chain"]
        self.assertGreaterEqual(len(chain), 3)
        self.assertEqual(chain[0]["id"], root["id"])

        # 5) 公文报告：模型预览 + 真实 docx 包
        model_resp = await self.client.get("/api/fusion/report/model/F-1")
        self.assertEqual(model_resp.status_code, 200, model_resp.text)
        model = model_resp.json()["model"]
        self.assertEqual(model["target_url"], "https://a.example.edu.cn/admin?id=1")
        self.assertEqual(len(model["traffic"]["verification"]), 1)
        self.assertIn("summary", model_resp.json()["model"]["goals"])

        docx = await self.client.get("/api/fusion/report/docx/F-1")
        self.assertEqual(docx.status_code, 200, docx.text[:400])
        self.assertIn("wordprocessingml.document", docx.headers["content-type"])
        self.assertEqual(docx.content[:2], b"PK")
        with zipfile.ZipFile(io.BytesIO(docx.content)) as zf:
            ET.fromstring(zf.read("word/document.xml"))
            document = zf.read("word/document.xml").decode("utf-8")
            self.assertIn("五、流量证据链", document)
            self.assertIn("SQL 注入可读取管理数据", document)

        # 6) 开关真正生效：关闭后写操作 409，且 GET /config 证明是合并而非覆盖
        off = await self.client.put("/api/fusion/config", json={"config": {
            "graphs_enabled": False, "report_enabled": False,
        }})
        self.assertEqual(off.status_code, 200, off.text)
        overlay = (await self.client.get("/api/fusion/config")).json()["overlay"]
        self.assertTrue(overlay["traffic_enabled"], "部分字段提交不得丢掉旧配置")
        self.assertEqual(overlay["intel_lookback_days"], 14)
        self.assertEqual((await self.client.post("/api/fusion/graphs/T-FUSION/rebuild")).status_code, 409)
        self.assertEqual((await self.client.get("/api/fusion/report/docx/F-1")).status_code, 409)

        back = await self.client.put("/api/fusion/config", json={"config": {
            "graphs_enabled": True, "report_enabled": True,
        }})
        self.assertEqual(back.status_code, 200, back.text)


if __name__ == "__main__":
    unittest.main()
