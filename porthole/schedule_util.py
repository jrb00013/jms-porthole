"""
Human-friendly duration parsing for scheduled/daemon-style commands
(`jms watch HOST --interval 5m`), reused wherever a command wants to accept
"5m", "1h", "30s", "90" (bare seconds) rather than requiring raw seconds.
"""

from __future__ import annotations

import re

_UNIT_SECONDS = {
    "s": 1,
    "sec": 1,
    "secs": 1,
    "m": 60,
    "min": 60,
    "mins": 60,
    "h": 3600,
    "hr": 3600,
    "hrs": 3600,
    "d": 86400,
}

_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$")


def parse_duration(spec: str | int | float) -> float:
    """
    Parse a duration spec into seconds. Accepts bare numbers (seconds) or a
    number followed by a unit: s/sec/secs, m/min/mins, h/hr/hrs, d.

    Raises ValueError on anything unparseable.
    """
    if isinstance(spec, (int, float)):
        if spec < 0:
            raise ValueError(f"Duration cannot be negative: {spec}")
        return float(spec)

    match = _PATTERN.match(spec)
    if not match:
        raise ValueError(f"Invalid duration: {spec!r}")

    value = float(match.group(1))
    unit = match.group(2).lower()

    if not unit:
        return value

    if unit not in _UNIT_SECONDS:
        raise ValueError(f"Unknown duration unit {unit!r} in {spec!r}")

    return value * _UNIT_SECONDS[unit]


def format_duration(seconds: float) -> str:
    """Render a seconds value back as a short human string, e.g. 300 -> '5m'."""
    seconds = int(seconds)
    if seconds % 86400 == 0 and seconds >= 86400:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0 and seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0 and seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"
