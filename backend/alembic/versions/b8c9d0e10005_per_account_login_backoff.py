"""per_account_login_backoff: failed_login_attempts and locked_until on users

Issue #127. The per-IP rate limit cannot protect a password from someone rotating
source addresses, so the counter lives on the account row. See
app/services/password_throttle.py for the reservation protocol.

Revision ID: b8c9d0e10005
Revises: a7b8c9d00004
Create Date: 2026-11-11 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8c9d0e10005'
down_revision: Union[str, None] = 'a7b8c9d00004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # NOT NULL with a server default, so existing rows start at 0. The reservation is a
    # compare-and-swap on equality, and NULL = 0 is not true in SQL.
    op.add_column(
        'users',
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column('users', sa.Column('locked_until', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_attempts')
