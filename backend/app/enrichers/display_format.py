"""dashboard display formatting helpers for logs and user-facing output."""


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
