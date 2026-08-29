def format_duration(seconds: int | None) -> str:
    """Format a duration in seconds for human-readable CLI output."""
    if seconds is None:
        return "unknown"

    if seconds == 0:
        return "0 seconds"

    units = (
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
    )

    for name, unit_seconds in units:
        if seconds % unit_seconds == 0:
            value = seconds // unit_seconds
            suffix = "" if value == 1 else "s"
            return f"{value} {name}{suffix}"

    suffix = "" if seconds == 1 else "s"
    return f"{seconds} second{suffix}"
