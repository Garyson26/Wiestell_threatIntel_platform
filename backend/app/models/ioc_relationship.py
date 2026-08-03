"""IOC Relationship database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.types import NaiveUTCDateTime


class IOCRelationship(Base):
    __tablename__ = "ioc_relationships"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_ioc_id = Column(
        String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    target_ioc_id = Column(
        String(36), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type = Column(String(50))  # resolves_to, contains, communicates_with, drops, hosts
    confidence = Column(Integer, default=50)
    created_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # Relationships
    source_ioc = relationship("IOC", foreign_keys=[source_ioc_id], back_populates="outgoing_relationships")
    target_ioc = relationship("IOC", foreign_keys=[target_ioc_id], back_populates="incoming_relationships")

    __table_args__ = (
        UniqueConstraint(
            "source_ioc_id", "target_ioc_id", "relationship_type",
            name="uq_ioc_relationship",
        ),
    )

    def __repr__(self):
        return f"<IOCRelationship({self.source_ioc_id} -> {self.target_ioc_id}, type={self.relationship_type})>"
