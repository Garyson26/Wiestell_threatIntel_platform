"""harden_otp_table: store hashed codes, add purpose and attempt counter

Revision ID: d4e5f6a70001
Revises: c3d4e5f67890
Create Date: 2026-07-28 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a70001'
down_revision: Union[str, None] = 'c3d4e5f67890'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Codes are now stored as a keyed SHA-256 hex digest (64 chars) instead of
    # the plaintext 6-digit value.
    op.alter_column(
        'otps',
        'otp',
        existing_type=sa.String(length=10),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
    op.add_column(
        'otps',
        sa.Column('purpose', sa.String(length=20), nullable=False, server_default='login'),
    )
    op.add_column(
        'otps',
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
    )
    # Any code issued before this migration is a plaintext value that can no
    # longer be verified — drop them so nothing is left in a usable state.
    op.execute("DELETE FROM otps")


def downgrade() -> None:
    op.drop_column('otps', 'attempts')
    op.drop_column('otps', 'purpose')
    op.execute("DELETE FROM otps")
    op.alter_column(
        'otps',
        'otp',
        existing_type=sa.String(length=255),
        type_=sa.String(length=10),
        existing_nullable=False,
    )
