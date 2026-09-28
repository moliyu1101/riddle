"""pytest 共享配置：把项目根加入 sys.path，使 `import app.*` 在任何运行方式下都成立。

各测试文件里的同款样板保留无害；新测试文件无需再复制。
另外：整个测试会话统一用临时 SQLite 库（在 app 任何模块 import 之前生效），
集成测试与单元测试都不碰开发者的真实数据。
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "DB_PATH" not in os.environ:
    _TMP_DB_DIR = Path(tempfile.mkdtemp(prefix="_riddle_test_db_"))
    os.environ["DB_PATH"] = str(_TMP_DB_DIR / "riddle.db")
