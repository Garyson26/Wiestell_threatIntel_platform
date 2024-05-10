"""friendly indicator count formatting for logs and user-facing output."""


SIZE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"]


def human_size(count):
    """Render a byte count using binary-scaled units."""
    sign = "-" if count < 0 else ""
    value = float(abs(count))
    for unit in SIZE_UNITS:
        if value < 1024.0 or unit == SIZE_UNITS[-1]:
            if unit == "B":
                return "%s%d B" % (sign, int(value))
            return "%s%.1f %s" % (sign, value, unit)
        value /= 1024.0


def readable_time(seconds):
    """Render a duration in seconds as a compact string."""
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm %ds" % (seconds // 60, seconds % 60)
    return "%dh %dm" % (seconds // 3600, (seconds % 3600) // 60)
