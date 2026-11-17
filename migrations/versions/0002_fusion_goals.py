"""fusion_goals：目标闸门持久化表，幂等迁移。

init_db() 的顺序是 create_all（新表）→ 历史幂等迁移 → alembic upgrade head。
因此本表在绝大多数部署里由 create_all 先建好；这里显式判断表是否存在，
存在则跳过，保证「新库 stamp head」与「老库 upgrade head」两条路径都不报错。

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("fusion_goals"):
        return
    op.create_table(
        "fusion_goals",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("task_id", sa.String(32), nullable=False, index=True),
        sa.Column("goal_key", sa.String(64), nullable=False, server_default=""),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("criteria", sa.Text(), nullable=False, server_default=""),
        sa.Column("kind", sa.String(20), nullable=False, server_default="existence"),
        sa.Column("match_terms", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("evidence_ref", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_fusion_goals_task_id", "fusion_goals", ["task_id"])
    op.create_index("ix_fusion_goals_status", "fusion_goals", ["status"])
    op.create_index(
        "ux_fusion_goals_task_key", "fusion_goals", ["task_id", "goal_key"], unique=True
    )


def downgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("fusion_goals"):
        op.drop_table("fusion_goals")
