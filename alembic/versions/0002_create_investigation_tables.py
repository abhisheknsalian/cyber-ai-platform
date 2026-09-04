"""create investigation tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-04

investigations.latest_classification_id and classification_results.investigation_id
form a circular foreign-key pair: investigations can't be created with that FK inline
(classification_results doesn't exist yet), so `latest_classification_id` is created
here as a plain nullable INTEGER column and the FK constraint itself is added
afterward, once both tables exist, via `create_foreign_key` inside
`batch_alter_table`. Batch mode is required for portability: SQLite has no native
`ALTER TABLE ... ADD CONSTRAINT` (Alembic transparently recreates the table there
instead), while on PostgreSQL the same call compiles to a plain `ALTER TABLE ADD
CONSTRAINT` -- one migration, correct on both engines (verified against both; see
the project's README "Database Architecture").
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LATEST_CLASSIFICATION_FK = "fk_investigations_latest_classification_id"


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        # FK to classification_results.id added below, once that table exists.
        sa.Column("latest_classification_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_investigations_user_id", "investigations", ["user_id"])

    op.create_table(
        "classification_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "investigation_id",
            sa.Integer(),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("prediction", sa.String(length=32), nullable=False),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("probability", sa.Float(), nullable=True),
        sa.Column("class_probabilities", sa.JSON(), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_classification_results_investigation_id", "classification_results", ["investigation_id"]
    )

    op.create_table(
        "analysis_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "classification_result_id",
            sa.Integer(),
            sa.ForeignKey("classification_results.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("threat", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("attack_vectors", sa.JSON(), nullable=True),
        sa.Column("mitre_attack", sa.JSON(), nullable=True),
        sa.Column("indicators", sa.JSON(), nullable=True),
        sa.Column("mitigations", sa.JSON(), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # The deferred half of the circular FK -- see module docstring.
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.create_foreign_key(
            _LATEST_CLASSIFICATION_FK,
            "classification_results",
            ["latest_classification_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_constraint(_LATEST_CLASSIFICATION_FK, type_="foreignkey")

    op.drop_table("analysis_results")

    op.drop_index("ix_classification_results_investigation_id", table_name="classification_results")
    op.drop_table("classification_results")

    op.drop_index("ix_investigations_user_id", table_name="investigations")
    op.drop_table("investigations")
