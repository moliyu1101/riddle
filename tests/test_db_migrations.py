"""Alembic 迁移对齐回归：init_db 后 stamp 到 head、幂等、增量 upgrade 路径可用。"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class AlembicAlignTest(unittest.IsolatedAsyncioTestCase):
    async def test_stamp_head_then_upgrade_idempotent(self):
        """临时库：init_db → alembic_version=head；二次 init_db 幂等；upgrade 增量路径通。"""
        tmp = tempfile.mkdtemp(prefix="_mig_test_")
        os.environ["DB_PATH"] = str(Path(tmp) / "riddle.db")
        try:
            # 隔离环境：重新加载模块使其按临时 DB_PATH 建引擎
            import importlib

            from app.db import session as dbmod
            importlib.reload(dbmod)
            await dbmod.init_db()

            from alembic.config import Config
            from alembic.script import ScriptDirectory
            from sqlalchemy import text

            async with dbmod.engine.connect() as conn:
                has_version = (await conn.execute(text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
                ))).scalar()
            self.assertTrue(has_version, "init_db 后必须有 alembic_version")
            async with dbmod.engine.connect() as conn:
                conn_ver = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
            cfg = Config(str(ROOT / "alembic.ini"))
            head = ScriptDirectory.from_config(cfg).get_current_head()
            self.assertEqual(conn_ver, head)

            # 二次 init_db（走 upgrade 路径）幂等
            await dbmod.init_db()
            async with dbmod.engine.connect() as conn:
                ver = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
            self.assertEqual(ver, head)
        finally:
            os.environ.pop("DB_PATH", None)
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
