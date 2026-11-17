"""双图架构 + 流量留痕：三张旁路表，幂等迁移。

与 0002 同理：init_db 的 create_all 会先建表，本 revision 只在表不存在时补建，
保证新库 stamp head / 老库 upgrade head 两条路径都零冲突。

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("fusion_graph_nodes"):
        op.create_table(
            "fusion_graph_nodes",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("task_id", sa.String(32), nullable=False, index=True),
            sa.Column("graph", sa.String(20), nullable=False, server_default="asset"),
            sa.Column("kind", sa.String(30), nullable=False, server_default=""),
            sa.Column("label", sa.String(500), nullable=False, server_default=""),
            sa.Column("ref_id", sa.String(64), nullable=False, server_default=""),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_fgraph_nodes_task", "fusion_graph_nodes", ["task_id", "graph"])
    if not inspector.has_table("fusion_graph_edges"):
        op.create_table(
            "fusion_graph_edges",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("task_id", sa.String(32), nullable=False, index=True),
            sa.Column("kind", sa.String(30), nullable=False, server_default=""),
            sa.Column("src", sa.String(32), nullable=False, server_default=""),
            sa.Column("dst", sa.String(32), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_fgraph_edges_task", "fusion_graph_edges", ["task_id"])
    if not inspector.has_table("fusion_traffic"):
        op.create_table(
            "fusion_traffic",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("task_id", sa.String(32), nullable=False, index=True),
            sa.Column("finding_id", sa.String(32), nullable=False, server_default="", index=True),
            sa.Column("role", sa.String(20), nullable=False, server_default="supporting"),
            sa.Column("method", sa.String(10), nullable=False, server_default="GET"),
            sa.Column("url", sa.String(1000), nullable=False, server_default=""),
            sa.Column("status_code", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("request_head", sa.Text(), nullable=False, server_default=""),
            sa.Column("response_head", sa.Text(), nullable=False, server_default=""),
            sa.Column("body_sha256", sa.String(64), nullable=False, server_default="", index=True),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(), nullable=False, index=True),
        )
        op.create_index("ix_fusion_traffic_task", "fusion_traffic", ["task_id", "created_at"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for table in ("fusion_traffic", "fusion_graph_edges", "fusion_graph_nodes"):
        if inspector.has_table(table):
            op.drop_table(table)
