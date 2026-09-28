"""Unit tests for porthole.schedule_util — human-friendly duration parsing."""

import pytest

from porthole import schedule_util


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("30s", 30),
        ("5m", 300),
        ("1h", 3600),
        ("2d", 172800),
        ("90", 90),
        (90, 90),
        (90.5, 90.5),
        ("1.5h", 5400),
        ("10min", 600),
        ("2hrs", 7200),
    ],
)
def test_parse_duration_valid(spec, expected):
    assert schedule_util.parse_duration(spec) == expected


def test_parse_duration_rejects_negative_number():
    with pytest.raises(ValueError):
        schedule_util.parse_duration(-5)


def test_parse_duration_rejects_unknown_unit():
    with pytest.raises(ValueError):
        schedule_util.parse_duration("5x")


def test_parse_duration_rejects_garbage():
    with pytest.raises(ValueError):
        schedule_util.parse_duration("not-a-duration")


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (30, "30s"),
        (300, "5m"),
        (3600, "1h"),
        (86400, "1d"),
        (90, "90s"),
    ],
)
def test_format_duration(seconds, expected):
    assert schedule_util.format_duration(seconds) == expected
