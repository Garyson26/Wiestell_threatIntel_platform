"""Pydantic schemas for IOC operations."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import AliasChoices, BaseModel, Field


class IOCBase(BaseModel):
    type: str = Field(..., description="IOC type: ip, domain, hash, url, email, cve")
    value: str = Field(..., description="IOC value")
    tags: List[str] = Field(default_factory=list)
    metadata_: Optional[dict] = Field(
        default=None,
        validation_alias=AliasChoices("metadata_", "metadata"),
        serialization_alias="metadata",
    )
    mitre_techniques: List[str] = Field(default_factory=list)


class IOCCreate(IOCBase):
    threat_score: Optional[int] = Field(default=None, ge=0, le=100)
    confidence: Optional[int] = Field(default=None, ge=0, le=100)


class IOCUpdate(BaseModel):
    tags: Optional[List[str]] = None
    threat_score: Optional[int] = Field(default=None, ge=0, le=100)
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    mitre_techniques: Optional[List[str]] = None


class IOCResponse(IOCBase):
    id: UUID
    threat_score: int
    confidence: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    sighting_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class IOCDetailResponse(IOCResponse):
    enrichments: List[dict] = Field(default_factory=list)
    sources: List[dict] = Field(default_factory=list)
    relationships: List[dict] = Field(default_factory=list)


class IOCSearchRequest(BaseModel):
    query: Optional[str] = None
    ioc_type: Optional[str] = None
    min_score: Optional[int] = Field(default=None, ge=0, le=100)
    max_score: Optional[int] = Field(default=None, ge=0, le=100)
    tags: Optional[List[str]] = None
    feed_source: Optional[str] = None
    mitre_technique: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_by: str = Field(default="last_seen")
    sort_order: str = Field(default="desc")


class IOCBulkRequest(BaseModel):
    values: List[str] = Field(..., description="List of IOC values to look up")


class IOCExportRequest(BaseModel):
    format: str = Field(default="json", description="Export format: json, csv, stix")
    ioc_ids: Optional[List[UUID]] = None
    filters: Optional[IOCSearchRequest] = None


class IOCTagUpdate(BaseModel):
    tags: List[str]


class PaginatedIOCResponse(BaseModel):
    items: List[IOCResponse]
    total: int
    page: int
    page_size: int
    pages: int
