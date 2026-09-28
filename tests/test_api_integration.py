"""HTTP 层集成测试：真实启动 FastAPI 应用（含 startup 初始化），覆盖
核心端点、鉴权矩阵与任务 CRUD——此前全仓没有任何 HTTP 层测试，
REST/SSE 契约只靠前端手工对齐。

conftest.py 已把 DB_PATH 指向临时库，本文件不发真实网络请求、不碰开发者数据。
"""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 令牌走环境变量外的独立值：setUpClass 里通过设置 API 配置/清除（DB 持久化）
FULL_TOKEN = "it-full-token"
READ_TOKEN = "it-read-token"


class ApiIntegrationBase(unittest.TestCase):
    """整个类共享一个已启动的 TestClient（with 进入触发 startup）。"""

    client = None

    @classmethod
    def setUpClass(cls):
        for var in ("RIDDLE_API_TOKEN", "RIDDLE_READ_TOKEN", "RIDDLE_OBSERVER_TOKEN"):
            os.environ.pop(var, None)
        from fastapi.testclient import TestClient

        from app.main import app

        cls.client = TestClient(app)
        cls._ctx = cls.client.__enter__()  # 触发 startup（init_db/alembic 对齐）

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    @classmethod
    def _set_tokens(cls, full: str | None, read: str | None = None, observer: str | None = None):
        """None=不改该项；空串=清除该令牌（settings_service 约定空串即清除）。"""
        auth = {}
        if full is not None:
            auth["full_token"] = full
        if read is not None:
            auth["read_token"] = read
        if observer is not None:
            auth["observer_token"] = observer
        res = cls.client.put("/api/settings", json={"auth": auth},
                             headers={"X-Riddle-Token": FULL_TOKEN})
        cls._last_auth_put = res

    def _auth_cleanup(self):
        # 清除全部自定义令牌（空串=清除），恢复无令牌模式
        self._set_tokens("", "", "")


class CoreEndpointsTest(ApiIntegrationBase):
    def test_health_and_about(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        about = self.client.get("/api/about")
        self.assertEqual(about.status_code, 200)
        self.assertIn("name", about.json())

    def test_index_served(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("知蠹 Riddle", res.text)

    def test_task_crud_roundtrip(self):
        created = self.client.post("/api/tasks", json={
            "name": "it-integration", "src_type": "edusrc",
            "vuln_types": ["未授权访问"], "target_source": "manual",
            "manual_targets": ["https://it.example.edu.cn"],
            "concurrency": 1, "deepen_cap": 0,
        })
        self.assertEqual(created.status_code, 200, created.text)
        tid = created.json()["id"]
        try:
            listing = self.client.get("/api/tasks")
            self.assertEqual(listing.status_code, 200)
            self.assertTrue(any(t["id"] == tid for t in listing.json()))
        finally:
            gone = self.client.delete(f"/api/tasks/{tid}")
            self.assertIn(gone.status_code, (200, 204))
        listing2 = self.client.get("/api/tasks")
        self.assertFalse(any(t["id"] == tid for t in listing2.json()))


class AuthMatrixTest(ApiIntegrationBase):
    def test_token_matrix_on_export(self):
        """配置三级令牌后：无令牌 401 / 只读 403（export 含密钥）/ 全权限 200。"""
        self._set_tokens(FULL_TOKEN, READ_TOKEN)
        try:
            # 无令牌
            self.assertEqual(self.client.get("/api/settings/export").status_code, 401)
            # 只读令牌：普通读 200，export 403，写 403
            h_read = {"X-Riddle-Token": READ_TOKEN}
            self.assertEqual(self.client.get("/api/settings", headers=h_read).status_code, 200)
            self.assertEqual(
                self.client.get("/api/settings/export", headers=h_read).status_code, 403)
            self.assertEqual(
                self.client.post("/api/tasks", json={"name": "x"}, headers=h_read).status_code,
                403)
            # 全权限令牌：export 200 且无 auth 段（令牌不出站）
            h_full = {"X-Riddle-Token": FULL_TOKEN}
            exp = self.client.get("/api/settings/export", headers=h_full)
            self.assertEqual(exp.status_code, 200)
            self.assertNotIn("auth", exp.json())
        finally:
            self._auth_cleanup()
        # 清除后恢复无令牌全权限
        self.assertEqual(self.client.get("/api/settings").status_code, 200)


if __name__ == "__main__":
    unittest.main()
