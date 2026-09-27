"""orchestrator 包：原单体 orchestrator.py 按职责拆分（行为不变）。

- runner.py      TaskRunner 组合类（状态容器 __init__）
- dispatch.py    调度：主循环/出队/探活/限流/worker 生命周期/控制面
- workers.py     worker 执行与查重/单站协作
- review.py      AI 初审/退避/打回深挖
- killsweep.py   通杀与扩大危害
- persistence.py trace 批量刷盘与各实体落库
- manager.py     多任务管理器（单例 manager）
外部引用保持兼容：from app.orchestrator import TaskRunner, manager, ...
"""
from app.orchestrator._common import *  # noqa: F401,F403
from app.orchestrator.runner import TaskRunner  # noqa: F401
from app.orchestrator.manager import OrchestratorManager, manager  # noqa: F401
