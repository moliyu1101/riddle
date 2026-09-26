"""pytest 共享配置：把项目根加入 sys.path，使 `import app.*` 在任何运行方式下都成立。

各测试文件里的同款样板保留无害；新测试文件无需再复制。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
