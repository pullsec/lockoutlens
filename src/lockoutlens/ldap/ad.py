from datetime import timedelta


AD_TICKS_PER_SECOND = 10_000_000


def ad_interval_to_seconds(
    value: int | str | timedelta | None,
) -> int | None:
    """Convert an Active Directory interval to seconds."""
    if value is None:
        return None

    if isinstance(value, timedelta):
        return abs(int(value.total_seconds()))

    ticks = int(value)

    return abs(ticks) // AD_TICKS_PER_SECOND
