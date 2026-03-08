"""Add registration data fields to OTP table

Revision ID: 004
Revises: 003
Create Date: 2026-03-08
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade():
    # Make user_id nullable (for signup OTPs where user doesn't exist yet)
    op.alter_column('otps', 'user_id',
                    existing_type=sa.dialects.postgresql.UUID(),
                    nullable=True)
    
    # Add columns to store temporary registration data
    op.add_column('otps', sa.Column('username', sa.String(255), nullable=True))
    op.add_column('otps', sa.Column('hashed_password', sa.String(255), nullable=True))
    op.add_column('otps', sa.Column('full_name', sa.String(255), nullable=True))
    op.add_column('otps', sa.Column('role', sa.String(50), nullable=True))


def downgrade():
    # Remove added columns
    op.drop_column('otps', 'role')
    op.drop_column('otps', 'full_name')
    op.drop_column('otps', 'hashed_password')
    op.drop_column('otps', 'username')
    
    # Make user_id non-nullable again
    op.alter_column('otps', 'user_id',
                    existing_type=sa.dialects.postgresql.UUID(),
                    nullable=False)
