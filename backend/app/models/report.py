"""Threat Report database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(300), nullable=False)
    report_type = Column(String(50), nullable=False)  # daily_brief, weekly_brief, custom, investigation
    summary = Column(Text)
    content = Column(JSONB, default=dict)  # Structured report data
    parameters = Column(JSONB, default=dict)  # Generation parameters (date range, filters, etc.)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_by = Column(String(100))

    def __repr__(self):
        return f"<Report(title={self.title}, type={self.report_type})>"
