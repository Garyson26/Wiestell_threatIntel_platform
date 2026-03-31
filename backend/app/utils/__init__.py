from datetime import datetime, timezone, timedelta
from typing import Optional

_IST = timezone(timedelta(hours=5, minutes=30))


def to_ist_str(dt: Optional[datetime]) -> Optional[str]:
    """Convert a naive UTC datetime (as stored in MySQL) to an IST ISO-8601 string.

    Returns None if dt is None.
    Example output: '2026-03-31T13:42:00+05:30'
    """
    if dt is None:
        return None
    # MySQL DateTime columns return naive datetimes; treat them as UTC.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_IST).isoformat()
