"""add_last_sync_error_to_feed_sources

Revision ID: c3d4e5f67890
Revises: b97d3e9a80e4
Create Date: 2026-03-29 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f67890'
down_revision: Union[str, None] = 'b97d3e9a80e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'feed_sources',
        sa.Column('last_sync_error', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('feed_sources', 'last_sync_error')
