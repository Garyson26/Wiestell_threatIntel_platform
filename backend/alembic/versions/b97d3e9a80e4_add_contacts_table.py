"""add_contacts_table

Revision ID: b97d3e9a80e4
Revises: 56fe08259401
Create Date: 2026-03-21 21:56:29.274342
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b97d3e9a80e4'
down_revision: Union[str, None] = '56fe08259401'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create contacts table
    op.create_table('contacts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('reason', sa.String(length=50), nullable=False),
    sa.Column('ioc', sa.String(length=500), nullable=True),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('is_resolved', sa.String(length=10), nullable=True),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # Create index on created_at for efficient sorting
    op.create_index('idx_contacts_created_at', 'contacts', [sa.text('created_at DESC')], unique=False)
    # Create index on email for searching
    op.create_index(op.f('ix_contacts_email'), 'contacts', ['email'], unique=False)


def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f('ix_contacts_email'), table_name='contacts')
    op.drop_index('idx_contacts_created_at', table_name='contacts')
    # Drop table
    op.drop_table('contacts')
