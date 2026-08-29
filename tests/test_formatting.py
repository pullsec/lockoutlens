import pytest

from lockoutlens.formatting import format_duration


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, "unknown"),
        (0, "0 seconds"),
        (1, "1 second"),
        (30, "30 seconds"),
        (60, "1 minute"),
        (1800, "30 minutes"),
        (3600, "1 hour"),
        (7200, "2 hours"),
        (86400, "1 day"),
        (3628800, "42 days"),
    ],
)
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected
