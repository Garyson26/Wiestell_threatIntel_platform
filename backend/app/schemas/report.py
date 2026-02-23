"""Pydantic schemas for Report operations."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field


class ReportCreate(BaseModel):
    title: str
    report_type: str = Field(default="custom", description="daily_brief, weekly_brief, custom, investigation")
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    ioc_ids: Optional[List[UUID]] = None
    feed_sources: Optional[List[str]] = None
    min_score: Optional[int] = None


class ReportResponse(BaseModel):
    id: UUID
    title: str
    report_type: str
    summary: Optional[str]
    content: dict
    parameters: dict
    generated_at: datetime
    created_by: Optional[str]

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    items: List[ReportResponse]
    total: int
