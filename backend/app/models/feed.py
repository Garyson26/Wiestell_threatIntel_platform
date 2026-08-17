"""Feed Source database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, Text, Boolean, JSON
from sqlalchemy import true as sa_true
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.types import NaiveUTCDateTime


class FeedSource(Base):
    __tablename__ = "feed_sources"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    feed_type = Column(String(20), nullable=False)  # api, csv, stix, custom
    url = Column(Text)
    api_key_env = Column(String(100))  # Env var name for API key
    # Soft-disable switch. Filtered on by the scheduler tick, feeds/sync-all,
    # dashboard/feed-health and report_generator — so clearing it is how a feed is
    # retired without deleting its ioc_sources links (see revision e5f6a7b80002).
    is_enabled = Column(Boolean, nullable=False, default=True, server_default=sa_true())
    sync_frequency = Column(Integer, default=3600)  # Seconds

    # ── Scheduling (revision a7b8c9d00004) ──────────────────────────────────
    # TWO TIMESTAMPS, TWO JOBS. Keep them distinct.
    #
    # `last_attempt_at` is the SCHEDULING input. Stamped at the attempt's START,
    # before the fetch, on every attempt including failures. Stamping at the start
    # is the whole point: computing next-due from completion makes every interval
    # `sync_frequency + sync_duration` and it drifts further each cycle.
    #
    # `last_sync_at` is the last SUCCESSFUL ingest, for dashboard/feed-health.
    # Unchanged, still stamped on success only. Do not read it for scheduling.
    #
    # The pair is also a health signal: last_attempt_at advancing while
    # last_sync_at stands still means the feed is broken rather than idle, which
    # nothing could express when one column did both jobs.
    last_attempt_at = Column(NaiveUTCDateTime, nullable=True)
    last_sync_at = Column(NaiveUTCDateTime)
    last_sync_status = Column(String(20))  # success, failed, partial
    last_sync_error = Column(Text, nullable=True)

    # Consecutive failed attempts, for back-off. `last_sync_status` holds only the
    # most recent outcome, so without this a feed failing for a week is
    # indistinguishable from one that failed once.
    consecutive_failures = Column(Integer, nullable=False, default=0, server_default="0")

    # ── Incremental fetch state (revision a7b8c9d00004) ─────────────────────
    # `sync_cursor` carries OTX's `modified_since`. It has its own column rather
    # than living in `config` because `FeedUpdate` replaces `config` wholesale, so
    # an operator editing config through the API would wipe machine-managed state
    # and silently reset the feed to a full re-fetch.
    sync_cursor = Column(Text, nullable=True)
    http_etag = Column(String(255), nullable=True)
    http_last_modified = Column(String(128), nullable=True)

    # ── Rolling-window continuity (revision f6a7b8c90003) ───────────────────
    # `last_ingest_watermark` is the latest source-record timestamp the previous
    # sync observed, for feeds whose connector sets `BaseFeed.rolling_window`.
    # `last_ingest_gap` records, in words, the most recent time the next file's
    # earliest record was *later* than this watermark — meaning records existed in
    # between and were never ingested. Silent data loss becomes a visible field.
    # Both stay NULL for full-catalogue feeds.
    last_ingest_watermark = Column(NaiveUTCDateTime, nullable=True)
    last_ingest_gap = Column(Text, nullable=True)
    ioc_count = Column(Integer, default=0)
    config = Column(JSON, default=dict)
    created_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # Relationships
    ioc_sources = relationship("IOCSource", back_populates="feed", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<FeedSource(name={self.name}, enabled={self.is_enabled})>"
