"""Threat Report database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, JSON

from app.database import Base
from app.models.types import NaiveUTCDateTime


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(300), nullable=False)
    report_type = Column(String(50), nullable=False)  # daily_brief, weekly_brief, custom, investigation
    summary = Column(Text)
    content = Column(JSON, default=dict)  # Structured report data
    parameters = Column(JSON, default=dict)  # Generation parameters (date range, filters, etc.)
    generated_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    created_by = Column(String(100))

    def __repr__(self):
        return f"<Report(title={self.title}, type={self.report_type})>"
