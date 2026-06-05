"""
Timezone-aware time helpers.

Background: most of the codebase uses ``datetime.now()`` (naive) and
``datetime.now(timezone.utc)`` interchangeably. Naive ISO strings like
``"2026-06-05T10:30:00"`` are ambiguous — when the dashboard does
``new Date(s).toLocaleString()`` in the browser, JavaScript interprets the
string as **local time**, which silently misrepresents UTC timestamps.

This module provides one helper, ``now_iso()``, that always returns a
timezone-aware ISO string of the form ``"2026-06-05T16:00:00+05:30"`` (or
whatever offset matches the container's TZ env var). Browsers parse the
offset correctly and render in the user's local timezone.

Storage convention going forward:
- ``now_iso()`` for any timestamp written to Redis or returned by the API.
- ``datetime.now(timezone.utc)`` is still fine when the call site explicitly
  wants UTC — those write ``...+00:00`` which the browser also handles.
"""
from datetime import datetime


def now_iso() -> str:
    """Return current local time as a TZ-aware ISO 8601 string.

    Example output (with TZ=Asia/Kolkata):
        "2026-06-05T16:00:00.123456+05:30"
    """
    return datetime.now().astimezone().isoformat()


def now() -> datetime:
    """Return current local time as a TZ-aware ``datetime``."""
    return datetime.now().astimezone()
