"""IOC (Indicator of Compromise) database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Text, DateTime, Index,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(String(20), nullable=False, index=True)  # ip, domain, hash, url, email, cve
    value = Column(Text, nullable=False)
    threat_score = Column(Integer, default=0)  # 0-100
    confidence = Column(Integer, default=0)     # 0-100
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    sighting_count = Column(Integer, default=1)
    tags = Column(ARRAY(Text), default=list)
    metadata_ = Column("metadata", JSONB, default=dict)
    mitre_techniques = Column(ARRAY(Text), default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    enrichments = relationship("Enrichment", back_populates="ioc", cascade="all, delete-orphan")
    sources = relationship("IOCSource", back_populates="ioc", cascade="all, delete-orphan")
    outgoing_relationships = relationship(
        "IOCRelationship",
        foreign_keys="IOCRelationship.source_ioc_id",
        back_populates="source_ioc",
        cascade="all, delete-orphan",
    )
    incoming_relationships = relationship(
        "IOCRelationship",
        foreign_keys="IOCRelationship.target_ioc_id",
        back_populates="target_ioc",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_ioc_type_value"),
        Index("idx_iocs_threat_score", threat_score.desc()),
        Index("idx_iocs_last_seen", last_seen.desc()),
        Index("idx_iocs_tags", tags, postgresql_using="gin"),
        Index("idx_iocs_metadata", "metadata", postgresql_using="gin"),
    )

    def __repr__(self):
        return f"<IOC(type={self.type}, value={self.value}, score={self.threat_score})>"
