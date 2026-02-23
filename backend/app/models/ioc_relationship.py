"""IOC Relationship database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class IOCRelationship(Base):
    __tablename__ = "ioc_relationships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_ioc_id = Column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    target_ioc_id = Column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type = Column(String(50))  # resolves_to, contains, communicates_with, drops, hosts
    confidence = Column(Integer, default=50)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

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
