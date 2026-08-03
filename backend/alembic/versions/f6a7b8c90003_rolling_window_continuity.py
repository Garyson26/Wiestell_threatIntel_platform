"""rolling_window_continuity: detect records lost between syncs of a rolling export

A rolling-window feed publishes "the last N hours" of records. If the interval
between two syncs exceeds N, every record that appeared and aged out in between is
never ingested — and nothing complains, because each individual sync looks
perfectly healthy: HTTP 200, a full file, hundreds of new IOCs, status "success".

MalwareBazaar's public export is the case that prompted this. Measured 2026-07-30:
881 samples spanning 47.78 hours. The file also looks entry-capped rather than
time-bounded, so a campaign spike shrinks the window without anything changing on
our side — meaning a margin that is comfortable today can quietly stop being so.

Two columns make that visible:

``last_ingest_watermark``
    The latest source-record timestamp the previous sync observed. Only advances,
    never retreats, so a short or partial file cannot lower it and manufacture a
    false gap on the following run.

``last_ingest_gap``
    Human-readable description of the most recent discontinuity — set when the new
    file's *earliest* record is later than the stored watermark, which means
    records existed between the two and were never seen. NULL when contiguous.

Both stay NULL for full-catalogue feeds (CISA KEV, eCrimeLabs, MISP CERT-FR): the
check is opt-in per connector via ``BaseFeed.rolling_window``, because
``_make_ioc`` defaults an absent timestamp to now() and a timestamp-free source
would otherwise report a gap on every single sync.

Revision ID: f6a7b8c90003
Revises: e5f6a7b80002
Create Date: 2026-07-30 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c90003'
down_revision: Union[str, None] = 'e5f6a7b80002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nullable with no server default: NULL means "no sync has recorded a window
    # yet", which the continuity check reads as "no evidence either way" and
    # therefore not a gap. A first sync after this migration establishes the
    # watermark without reporting a spurious loss.
    op.add_column(
        'feed_sources',
        sa.Column('last_ingest_watermark', sa.DateTime(), nullable=True),
    )
    op.add_column(
        'feed_sources',
        sa.Column('last_ingest_gap', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('feed_sources', 'last_ingest_gap')
    op.drop_column('feed_sources', 'last_ingest_watermark')
