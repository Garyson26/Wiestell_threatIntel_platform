"""Add OTP table.

Revision ID: 002
Revises: 001
Create Date: 2026-03-03 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # OTPs table
    op.create_table(
        "otps",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("otp", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified", sa.String(10), server_default="'pending'"),
    )
    op.create_index("idx_otps_username", "otps", ["username"])
    op.create_index("idx_otps_expires_at", "otps", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_otps_expires_at", table_name="otps")
    op.drop_index("idx_otps_username", table_name="otps")
    op.drop_table("otps")
