"""Enrichment result database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class Enrichment(Base):
    __tablename__ = "enrichments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id = Column(UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(50), nullable=False)  # whois, dns, geoip, shodan, reputation
    data = Column(JSONB, nullable=False)
    enriched_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True))

    # Relationships
    ioc = relationship("IOC", back_populates="enrichments")

    __table_args__ = (
        UniqueConstraint("ioc_id", "source", name="uq_enrichment_ioc_source"),
    )

    def __repr__(self):
        return f"<Enrichment(ioc_id={self.ioc_id}, source={self.source})>"
