"""dashboard display formatting helpers for logs and user-facing output."""


SIZE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"]


def human_size(count):
    """Render a byte count using binary-scaled units."""
    value = float(count)
    for unit in SIZE_UNITS:
        if value < 1024.0 or unit == SIZE_UNITS[-1]:
            return "%.1f %s" % (value, unit) if unit != "B" else "%d B" % int(value)
        value /= 1024.0
