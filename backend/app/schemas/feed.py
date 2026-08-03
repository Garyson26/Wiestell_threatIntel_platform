"""Pydantic schemas for Feed operations."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.config import ALLOWED_FEED_API_KEY_ENVS


def _validate_api_key_env(value: Optional[str]) -> Optional[str]:
    """Restrict which environment variable a feed may read its API key from.

    Without this, a feed row could point at SECRET_KEY / DATABASE_URL /
    EMAIL_PASSWORD and the sync worker would forward that value to a
    third-party endpoint as an API key.
    """
    if value in (None, ""):
        return None
    if value not in ALLOWED_FEED_API_KEY_ENVS:
        raise ValueError(
            "api_key_env must be one of: " + ", ".join(sorted(ALLOWED_FEED_API_KEY_ENVS))
        )
    return value


class FeedBase(BaseModel):
    name: str
    description: Optional[str] = None
    feed_type: str = Field(..., description="Feed type: api, csv, stix, custom")
    url: Optional[str] = None
    sync_frequency: int = Field(default=3600, description="Sync frequency in seconds")


class FeedCreate(FeedBase):
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    api_key_env: Optional[str] = None
    config: Optional[dict] = None

    @field_validator("api_key_env")
    @classmethod
    def _check_api_key_env(cls, v: Optional[str]) -> Optional[str]:
        return _validate_api_key_env(v)


class FeedUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    sync_frequency: Optional[int] = None
    url: Optional[str] = None
    api_key_env: Optional[str] = None
    config: Optional[dict] = None

    @field_validator("api_key_env")
    @classmethod
    def _check_api_key_env(cls, v: Optional[str]) -> Optional[str]:
        return _validate_api_key_env(v)


class FeedResponse(FeedBase):
    id: str  # Changed from UUID to str to match Feed model
    slug: str
    api_key_env: Optional[str]
    is_enabled: bool
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]
    last_sync_error: Optional[str] = None
    ioc_count: Optional[int] = 0
    config: Optional[dict] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

    @field_validator("last_sync_error", "url", mode="before")
    @classmethod
    def _redact_error(cls, v: Optional[str]) -> Optional[str]:
        """Never return a configured secret verbatim.

        ``last_sync_error`` is the original reason: driver and httpx errors embed
        connection URIs and, for abuse.ch's v2 exports, an Auth-Key in the URL path.

        ``url`` was added 2026-07-30 as defence in depth. It holds no key today —
        every connector's class-level ``url`` is keyless and the keyed variant is
        built into a local inside ``fetch()``, with nothing anywhere assigning
        ``feed.url``. But ``url`` *is* operator-settable through ``FeedCreate`` /
        ``FeedUpdate``, and feed reads are authenticated only at viewer level, so an
        admin pasting `.../v2/files/exports/<KEY>/recent.csv` by hand would publish
        that key to every user of the platform. Same class as H-03.

        ``redact_secrets`` rewrites only *configured secret values*, so ordinary
        keyless URLs are returned unchanged and the feeds UI is unaffected.
        """
        if not v:
            return v
        from app.utils.sanitize import redact_secrets

        return redact_secrets(v)


class FeedSyncLog(BaseModel):
    feed_id: str  # Changed from UUID to str
    feed_name: str
    status: str
    iocs_ingested: int
    timestamp: datetime
    error: Optional[str] = None
