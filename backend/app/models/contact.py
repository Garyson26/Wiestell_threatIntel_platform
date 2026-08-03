"""Contact message database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text

from app.database import Base
from app.models.types import NaiveUTCDateTime


class Contact(Base):
    """Contact message model for storing user inquiries."""
    __tablename__ = "contacts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    email = Column(String(255), nullable=False)
    reason = Column(String(50), nullable=False)  # feed-issue, api-access, feature-request, abuse-report
    ioc = Column(String(500), nullable=True)  # Optional IOC/Indicator field
    message = Column(Text, nullable=False)
    created_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    # Optional fields for tracking response
    is_resolved = Column(String(10), default="pending")  # pending, in-progress, resolved
    resolved_at = Column(NaiveUTCDateTime, nullable=True)
    notes = Column(Text, nullable=True)  # Internal notes for tracking

    def __repr__(self):
        return f"<Contact(id={self.id}, name={self.name}, reason={self.reason}, created_at={self.created_at})>"
