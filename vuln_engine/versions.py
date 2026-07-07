"""Tolerant version parsing and range comparison.

Software versions in the wild are not all PEP 440 compliant (e.g. OpenSSH
``8.9p1``, Apache ``2.4.49``). We try :class:`packaging.version.Version` first
and fall back to a normalized numeric-dotted form so comparisons still work.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_NUMERIC_PREFIX = re.compile(r"^\D*(\d+(?:\.\d+)*)")


def parse_version(raw: str | None) -> Version | None:
    if not raw:
        return None
    raw = raw.strip()
    try:
        return Version(raw)
    except InvalidVersion:
        m = _NUMERIC_PREFIX.match(raw)
        if not m:
            return None
        try:
            return Version(m.group(1))
        except InvalidVersion:
            return None


def in_range(
    version: str | None,
    start: str | None,
    start_incl: bool,
    end: str | None,
    end_incl: bool,
) -> bool:
    """True if ``version`` falls within [start, end] respecting inclusivity.

    A missing bound is treated as unbounded on that side. If the version cannot
    be parsed we return False (callers treat that as "needs review", not a match).
    """
    v = parse_version(version)
    if v is None:
        return False

    if start is not None:
        s = parse_version(start)
        if s is not None:
            if start_incl and v < s:
                return False
            if not start_incl and v <= s:
                return False

    if end is not None:
        e = parse_version(end)
        if e is not None:
            if end_incl and v > e:
                return False
            if not end_incl and v >= e:
                return False

    return True
