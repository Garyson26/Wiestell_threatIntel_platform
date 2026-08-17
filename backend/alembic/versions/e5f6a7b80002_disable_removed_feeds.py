"""disable_removed_feeds: soft-disable PhishTank and VirusTotal, tighten is_enabled

The PhishTank and VirusTotal connector modules were deleted on 2026-07-29. Their
``feed_sources`` rows are **deliberately not deleted**: ``ioc_sources`` still
links them to every indicator they contributed, and that table is what feeds
``COUNT(DISTINCT feed_id)`` in the source-diversity term. Deleting the rows would
cascade the links away and silently lower ``threat_score`` for each of those
indicators — an uncontrolled score change on top of the controlled one being
applied by ``scripts/rescore_corpus.py``.

Soft-disabling is enough to stop them syncing: the scheduler tick,
``feeds/sync-all``, ``dashboard/feed-health`` and ``report_generator`` all filter
on ``is_enabled``.

Note that no new column is added. An earlier plan called for an ``enabled``
column, but ``is_enabled`` has existed since the initial schema and is already
the filter every consumer uses; a second flag would split the meaning of
"enabled" across two fields. What was genuinely missing is the ``NOT NULL``
constraint — the initial migration declared it nullable, so a row could sit in a
third state that reads as disabled by ``== True`` but as enabled by a naive
truthiness check.

Revision ID: e5f6a7b80002
Revises: d4e5f6a70001
Create Date: 2026-07-29 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b80002'
down_revision: Union[str, None] = 'd4e5f6a70001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_REMOVED_FEED_SLUGS = ('virustotal', 'phishtank')


def upgrade() -> None:
    # Backfill before the constraint: a NULL here means "never explicitly set",
    # and the model default has always been True.
    op.execute("UPDATE feed_sources SET is_enabled = 1 WHERE is_enabled IS NULL")

    op.alter_column(
        'feed_sources',
        'is_enabled',
        existing_type=sa.Boolean(),
        nullable=False,
        server_default=sa.true(),
    )

    # Idempotent, and a no-op if the rows were never seeded — the entries were
    # commented out of scripts/seed_feeds.py before this change. Confirmed against
    # production's exact row set on 2026-08-17: 8 canonical feeds, neither removed slug
    # present, and this UPDATE matches zero rows and leaves every is_enabled at 1.
    #
    # Bound parameters rather than an f-string interpolation of the tuple. The previous
    # form was `f"WHERE slug IN {_REMOVED_FEED_SLUGS}"`, which is correct only while the
    # tuple has two or more entries: Python renders a ONE-element tuple as
    # `('virustotal',)`, and that trailing comma is a syntax error — verified, MariaDB
    # rejects it with 1064. Dropping either slug from the tuple would have broken the
    # migration at deploy time, which is precisely when it is least welcome.
    op.execute(
        sa.text(
            "UPDATE feed_sources SET is_enabled = 0 WHERE slug IN :slugs"
        ).bindparams(
            sa.bindparam("slugs", value=list(_REMOVED_FEED_SLUGS), expanding=True)
        )
    )


def downgrade() -> None:
    """Deliberately a no-op.

    Two reasons, both about not doing harm:

    * ``is_enabled`` predates this revision, so there is no column to drop. The
      ``NOT NULL`` tightening is left in place — loosening it back would restore
      a state nothing wants, and every row now holds a real boolean.
    * Re-enabling ``virustotal`` and ``phishtank`` would be actively wrong. Their
      connector modules no longer exist, so the scheduler would resolve neither
      slug in ``FEED_CONNECTORS``; every sync attempt would log
      ``scheduler_no_connector`` and the feed would sit permanently overdue.

    Re-enabling either row is a manual decision that belongs with whoever
    restores the connector code.
    """
