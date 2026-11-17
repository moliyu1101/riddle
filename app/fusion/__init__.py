"""融合层：把 Pojun（破军）的五项方法论用纯 Python 重写进 Riddle。

边界说明（合规）：本包**不包含、不复制**任何 Pojun/破军的 Go 源码、提示词原文或
技能文档，只实现同类机制（目标闸门、证据闸门、范围守卫、情报时间流、角色路由）。
Pojun 为 AGPL-3.0、Riddle 为 CC BY-NC 4.0，两者保持独立代码与独立许可。

模块：
  config         环境变量配置（不写库、不改 settings_service）
  goal_gate      目标 + 可核验验收标准 + goal_met 收官闸门 + 诚实终态
  evidence_gate  机械验证凭据门禁 + L1-L4 影响分级
  scope_guard    写回范围守卫（own/source/foreign）+ 基础设施黑名单
  vulnintel      CVE 情报时间流同步与资产指纹反查
  role_router    按角色配模型 + 技能速查块注入 system prompt
"""
from __future__ import annotations

__all__ = [
    "config",
    "goal_gate",
    "evidence_gate",
    "scope_guard",
    "vulnintel",
    "role_router",
]
