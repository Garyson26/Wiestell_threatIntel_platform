"""Pydantic schemas for Feed operations."""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class FeedBase(BaseModel):
    name: str
    description: Optional[str] = None
    feed_type: str = Field(..., description="Feed type: api, csv, stix, custom")
    url: Optional[str] = None
    sync_frequency: int = Field(default=3600, description="Sync frequency in seconds")


class FeedCreate(FeedBase):
    slug: str
    api_key_env: Optional[str] = None
    config: Optional[dict] = None


class FeedUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    sync_frequency: Optional[int] = None
    url: Optional[str] = None
    config: Optional[dict] = None


class FeedResponse(FeedBase):
    id: UUID
    slug: str
    api_key_env: Optional[str]
    is_enabled: bool
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]
    ioc_count: int
    config: dict
    created_at: datetime

    class Config:
        from_attributes = True


class FeedSyncLog(BaseModel):
    feed_id: UUID
    feed_name: str
    status: str
    iocs_ingested: int
    timestamp: datetime
    error: Optional[str] = None
