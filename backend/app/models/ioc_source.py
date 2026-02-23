"""IOC Source mapping (many-to-many between IOCs and Feed Sources)."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class IOCSource(Base):
    __tablename__ = "ioc_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id = Column(UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    feed_id = Column(UUID(as_uuid=True), ForeignKey("feed_sources.id", ondelete="CASCADE"), nullable=False)
    raw_data = Column(JSONB)
    ingested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    ioc = relationship("IOC", back_populates="sources")
    feed = relationship("FeedSource", back_populates="ioc_sources")

    __table_args__ = (
        UniqueConstraint("ioc_id", "feed_id", name="uq_ioc_source_ioc_feed"),
    )

    def __repr__(self):
        return f"<IOCSource(ioc_id={self.ioc_id}, feed_id={self.feed_id})>"
