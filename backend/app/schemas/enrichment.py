"""Pydantic schemas for Enrichment operations."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EnrichmentResponse(BaseModel):
    id: str  # Changed from UUID to str to match Enrichment model
    ioc_id: str  # Changed from UUID to str
    source: str
    data: dict
    enriched_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class EnrichmentRequest(BaseModel):
    sources: list[str] = ["whois", "dns", "geoip", "reputation"]
