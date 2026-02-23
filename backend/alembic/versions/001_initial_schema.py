"""Initial database schema.

Revision ID: 001
Revises: None
Create Date: 2025-01-01 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable required extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # IOCs table
    op.create_table(
        "iocs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("threat_score", sa.Integer, server_default="0"),
        sa.Column("confidence", sa.Integer, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("sighting_count", sa.Integer, server_default="1"),
        sa.Column("tags", ARRAY(sa.Text), server_default="{}"),
        sa.Column("metadata", JSONB, server_default="{}"),
        sa.Column("mitre_techniques", ARRAY(sa.Text), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.UniqueConstraint("type", "value", name="uq_ioc_type_value"),
    )
    op.create_index("idx_iocs_type", "iocs", ["type"])
    op.create_index("idx_iocs_threat_score", "iocs", [sa.text("threat_score DESC")])
    op.create_index("idx_iocs_last_seen", "iocs", [sa.text("last_seen DESC")])
    op.create_index("idx_iocs_tags", "iocs", ["tags"], postgresql_using="gin")
    op.create_index("idx_iocs_metadata", "iocs", ["metadata"], postgresql_using="gin")

    # Feed sources table
    op.create_table(
        "feed_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("feed_type", sa.String(20), nullable=False),
        sa.Column("url", sa.Text),
        sa.Column("api_key_env", sa.String(100)),
        sa.Column("is_enabled", sa.Boolean, server_default="true"),
        sa.Column("sync_frequency", sa.Integer, server_default="3600"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_sync_status", sa.String(20)),
        sa.Column("ioc_count", sa.Integer, server_default="0"),
        sa.Column("config", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    # Enrichments table
    op.create_table(
        "enrichments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ioc_id", "source", name="uq_enrichment_ioc_source"),
    )

    # IOC sources table (many-to-many)
    op.create_table(
        "ioc_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feed_id", UUID(as_uuid=True), sa.ForeignKey("feed_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("raw_data", JSONB),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.UniqueConstraint("ioc_id", "feed_id", name="uq_ioc_source_ioc_feed"),
    )

    # IOC relationships table
    op.create_table(
        "ioc_relationships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("source_ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(50)),
        sa.Column("confidence", sa.Integer, server_default="50"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.UniqueConstraint("source_ioc_id", "target_ioc_id", "relationship_type", name="uq_ioc_relationship"),
    )

    # MITRE ATT&CK techniques table
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("url", sa.Text),
        sa.Column("data_sources", ARRAY(sa.Text), server_default="{}"),
    )

    # Reports table
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("content", JSONB, server_default="{}"),
        sa.Column("parameters", JSONB, server_default="{}"),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("created_by", sa.String(100)),
    )

    # Users table
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.String(100), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(200)),
        sa.Column("role", sa.String(50), server_default="'analyst'"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("last_login", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("reports")
    op.drop_table("attack_techniques")
    op.drop_table("ioc_relationships")
    op.drop_table("ioc_sources")
    op.drop_table("enrichments")
    op.drop_table("feed_sources")
    op.drop_table("iocs")
