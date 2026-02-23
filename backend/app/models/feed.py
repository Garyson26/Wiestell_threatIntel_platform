"""Feed Source database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, Text, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class FeedSource(Base):
    __tablename__ = "feed_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    feed_type = Column(String(20), nullable=False)  # api, csv, stix, custom
    url = Column(Text)
    api_key_env = Column(String(100))  # Env var name for API key
    is_enabled = Column(Boolean, default=True)
    sync_frequency = Column(Integer, default=3600)  # Seconds
    last_sync_at = Column(DateTime(timezone=True))
    last_sync_status = Column(String(20))  # success, failed, partial
    ioc_count = Column(Integer, default=0)
    config = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    ioc_sources = relationship("IOCSource", back_populates="feed", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<FeedSource(name={self.name}, enabled={self.is_enabled})>"
