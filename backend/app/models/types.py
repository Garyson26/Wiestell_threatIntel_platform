"""Column types shared across the models.

Currently one: :class:`NaiveUTCDateTime`, which makes this project's naive-UTC
datetime convention enforced rather than merely documented.
"""

from datetime import datetime, timezone
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy import types


class NaiveUTCDateTime(types.TypeDecorator):
    """``DATETIME`` that normalises timezone-aware values to naive UTC on the way in.

    **Why this exists.** Every datetime in this schema is a timezone-naive UTC value,
    because MySQL ``DATETIME`` stores no offset. Passing a timezone-*aware* value does
    not raise — pymysql formats it and MySQL compares or stores the wall-clock reading,
    **silently discarding the offset**. Measured both directions:

    ==========  ======================================  ==========================
    Path        Aware input                             Result
    ==========  ======================================  ==========================
    comparison  ``11:00+05:30`` vs a naive column       compared as ``11:00``
    insertion   ``12:00+05:30`` into a naive column     stored as ``12:00``
    ==========  ======================================  ==========================

    Neither warns. This platform renders IST (+05:30) via :func:`app.utils.to_ist_str`,
    so an IST-aware value is the natural thing to reach for and the failure is a
    5.5-hour shift with no stack trace — wrong rows rather than an error. An audit on
    2026-07-30 found six sites passing aware values, every one correct *only* because
    UTC's offset happens to be zero.

    ``process_bind_param`` fires on **comparison operands**, not only inserts — verified
    empirically against MySQL 8.0.46, and per-bind-parameter, so it also covers ``IN``,
    ``BETWEEN`` and ``case()`` operands. That is what makes it a fix for the filter
    problem and not merely for writes.

    **It does not fire for raw** ``sa.text()`` **bound parameters** — no column type is
    in play, so the value goes straight to the driver. The CLAUDE.md caution therefore
    remains the control for raw SQL; ``scripts/rescore_corpus.py`` is built entirely on
    ``text()`` and passes no datetimes today, but is one edit from being affected.

    **No** ``process_result_value``, deliberately. Reads stay naive: returning aware
    values would be a wider behavioural change, ``to_ist_str()`` assumes naive input,
    and ``tests/test_mysql_integration.py`` pins naive reads. Writes and comparisons
    are coerced; reads are left alone.

    This changes no stored data. It only affects values crossing the boundary from
    Python, and every existing row is already naive UTC.
    """

    impl = sa.DateTime
    # Required. Without it SQLAlchemy emits a per-query caching warning rather than an
    # error, which is easy to miss in review.
    cache_ok = True

    def process_bind_param(
        self, value: Optional[datetime], dialect: Any
    ) -> Optional[datetime]:
        if value is not None and getattr(value, "tzinfo", None) is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value


def utcnow() -> datetime:
    """Naive UTC now, truncated to whole seconds.

    Truncation matters: MySQL ``DATETIME`` with no fractional-seconds precision
    **rounds** what it is given, so ``…:43.837451`` is stored as ``…:44``. A predicate
    comparing an untruncated Python value against the rounded stored one then fires or
    not depending on the microsecond fraction — that was a live non-deterministic bug in
    the ingestion re-read gate (PROJECT_SUMMARY.md §8 item 0e). ``feed_ingestion._now``
    truncates for the same reason.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


__all__ = ["NaiveUTCDateTime", "utcnow"]
