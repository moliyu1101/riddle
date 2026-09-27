"""baseline：存量库的 schema 演进由 app/db/session.py 的幂等迁移（加列/建索引/表重建）完成

init_db() 的对齐顺序：create_all（新表）→ 历史幂等迁移（补列/索引）→ 本处 stamp head。
存量库与新库都会被 stamp 到本版本；此后所有 schema 变更写新的 revision 文件，
不再手改 session.py 的 _MIGRATIONS（该清单冻结为历史记录）。

Revision ID: 0001
Revises:
Create Date: 2026-09-27
"""
from __future__ import annotations

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 基线为空操作：见 docstring。
    pass


def downgrade() -> None:
    pass
