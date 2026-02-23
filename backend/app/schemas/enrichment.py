"""Pydantic schemas for Enrichment operations."""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class EnrichmentResponse(BaseModel):
    id: UUID
    ioc_id: UUID
    source: str
    data: dict
    enriched_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class EnrichmentRequest(BaseModel):
    sources: list[str] = ["whois", "dns", "geoip", "reputation"]
