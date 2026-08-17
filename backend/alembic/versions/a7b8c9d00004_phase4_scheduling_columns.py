"""phase4_scheduling_columns: attempt timestamp, cursor, conditional-request and failure state

Phase 4 Section A. Five columns, reconciled down from the nine originally proposed in
``HANDOFF_SPEC_2_PLATFORM.md §Phase 4`` — see
``docs/superpowers/specs/2026-07-30-phase4-scheduling-design-notes.md`` §2.2 for the
reconciliation. ``enabled``, ``last_ingest_watermark`` and ``last_ingest_gap`` already
exist; ``sync_interval_minutes`` is redundant against ``sync_frequency``; ``next_due_at``
was cut (§2.3) because materialising a derived value lets a ``sync_frequency`` change
silently not take effect until each feed next runs.

``last_attempt_at`` — THE SCHEDULING FIX
    ``last_sync_at`` currently does two jobs: scheduling input, and "last successful
    ingest" for ``dashboard/feed-health``. It is stamped at *completion*, which means the
    next-due time is computed from when a sync FINISHED, so every interval silently
    becomes ``sync_frequency + sync_duration`` and drifts further each cycle. A feed
    configured for 6h at a 6h cron never fires on schedule at all.

    Splitting the field fixes scheduling without touching feed-health:

      last_attempt_at  scheduling input   stamped at attempt START, on EVERY attempt
                                          including failures
      last_sync_at     last SUCCESSFUL    unchanged, on success only
                       ingest

    The split also buys a signal that does not exist today: ``last_attempt_at`` advancing
    while ``last_sync_at`` stands still is precisely "this feed is broken, not idle". A
    permanently failing feed can currently look healthy.

    **Backfilled from ``last_sync_at``** so no feed is judged instantly overdue on the
    first tick after deploy. Production has 8 feed rows, all with a ``last_sync_at``, so
    this backfill is the difference between a normal first tick and all 8 firing at once.

``sync_cursor`` — its OWN column, deliberately
    For OTX's ``modified_since`` (Section D). It is tempting to put this in the existing
    ``config`` JSON column, but ``FeedUpdate`` replaces ``config`` wholesale, so an
    operator editing config through the API would silently wipe machine-managed cursor
    state and the next sync would re-fetch from the beginning. ``last_ingest_watermark``
    got a dedicated column for exactly this reason (§2.4).

``http_etag`` / ``http_last_modified`` — conditional requests, no equivalent exists today.

``consecutive_failures`` — back-off state. ``last_sync_status`` records only the most
    recent outcome, so there is currently no way to distinguish one blip from a feed that
    has been failing for a week. NOT NULL DEFAULT 0 because a NULL counter has no useful
    meaning and every consumer would have to coalesce it.

Revision ID: a7b8c9d00004
Revises: f6a7b8c90003
Create Date: 2026-08-17 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d00004'
down_revision: Union[str, None] = 'f6a7b8c90003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'feed_sources',
        sa.Column('last_attempt_at', sa.DateTime(), nullable=True),
    )
    op.add_column(
        'feed_sources',
        sa.Column('sync_cursor', sa.Text(), nullable=True),
    )
    # 255/128 rather than Text: both are HTTP header values echoed back verbatim in a
    # request header, and an unbounded column invites storing a response body by mistake.
    op.add_column(
        'feed_sources',
        sa.Column('http_etag', sa.String(255), nullable=True),
    )
    op.add_column(
        'feed_sources',
        sa.Column('http_last_modified', sa.String(128), nullable=True),
    )
    op.add_column(
        'feed_sources',
        sa.Column(
            'consecutive_failures',
            sa.Integer(),
            nullable=False,
            server_default='0',
        ),
    )

    # Backfill BEFORE anything reads the column. Without this every feed has
    # last_attempt_at IS NULL, which the smart-mode check reads as "never attempted" and
    # therefore overdue — so the first tick after deploy would fire all 8 production feeds
    # simultaneously, against a shared host, with no cadence spread.
    op.execute(
        "UPDATE feed_sources SET last_attempt_at = last_sync_at "
        "WHERE last_attempt_at IS NULL"
    )


def downgrade() -> None:
    op.drop_column('feed_sources', 'consecutive_failures')
    op.drop_column('feed_sources', 'http_last_modified')
    op.drop_column('feed_sources', 'http_etag')
    op.drop_column('feed_sources', 'sync_cursor')
    op.drop_column('feed_sources', 'last_attempt_at')
