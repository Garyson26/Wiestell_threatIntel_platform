"""Update OTP table to use email instead of username.

Revision ID: 003
Revises: 002
Create Date: 2026-03-05 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop the old username index
    op.drop_index("idx_otps_username", table_name="otps")
    
    # Rename column from username to email
    op.alter_column("otps", "username", new_column_name="email", existing_type=sa.String(100))
    
    # Update the column type to String(255) to match email field
    op.alter_column("otps", "email", type_=sa.String(255), existing_nullable=False)
    
    # Create new index on email
    op.create_index("idx_otps_email", "otps", ["email"])


def downgrade() -> None:
    # Drop the email index
    op.drop_index("idx_otps_email", table_name="otps")
    
    # Rename column back to username
    op.alter_column("otps", "email", new_column_name="username", type_=sa.String(100))
    
    # Recreate the username index
    op.create_index("idx_otps_username", "otps", ["username"])
