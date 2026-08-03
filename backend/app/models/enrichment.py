"""Enrichment result database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.types import NaiveUTCDateTime


class Enrichment(Base):
    __tablename__ = "enrichments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_id = Column(String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(50), nullable=False)  # whois, dns, geoip, shodan, reputation
    data = Column(JSON, nullable=False)
    enriched_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expires_at = Column(NaiveUTCDateTime)

    # Relationships
    ioc = relationship("IOC", back_populates="enrichments")

    __table_args__ = (
        UniqueConstraint("ioc_id", "source", name="uq_enrichment_ioc_source"),
    )

    def __repr__(self):
        return f"<Enrichment(ioc_id={self.ioc_id}, source={self.source})>"
