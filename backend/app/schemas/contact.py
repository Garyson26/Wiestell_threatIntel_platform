"""Pydantic schemas for Contact operations."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum


class ContactReasonEnum(str, Enum):
    """Enum for contact reasons."""
    FEED_ISSUE = "feed-issue"
    API_ACCESS = "api-access"
    FEATURE_REQUEST = "feature-request"
    ABUSE_REPORT = "abuse-report"


class ContactCreate(BaseModel):
    """Schema for creating a new contact message."""
    name: str = Field(..., min_length=1, max_length=200, description="Full name of the contact")
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", description="Email address")
    reason: ContactReasonEnum = Field(..., description="Reason for contacting")
    ioc: Optional[str] = Field(None, max_length=500, description="Optional IOC or indicator")
    message: str = Field(..., min_length=20, max_length=1000, description="Message content")


class ContactResponse(BaseModel):
    """Schema for contact message response."""
    id: str
    name: str
    email: str
    reason: str
    ioc: Optional[str]
    message: str
    is_resolved: str
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class ContactListResponse(BaseModel):
    """Schema for paginated contact list."""
    contacts: list[ContactResponse]
    total: int
    page: int
    page_size: int
