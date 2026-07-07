"""Data objects for the vulnerability engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CpeMatch:
    cpe: str  # cpe:2.3:a:vendor:product  (version part optional here)
    version_start: str | None = None
    version_start_incl: bool = False
    version_end: str | None = None
    version_end_incl: bool = False


@dataclass
class CveRecord:
    id: str
    description: str
    cvss_v3: float | None
    cvss_vector: str | None
    severity: str  # critical | high | medium | low
    cwe: str | None
    published: str | None
    references: list[str] = field(default_factory=list)
    matches: list[CpeMatch] = field(default_factory=list)
    fixed_version: str | None = None
    recommendation: str | None = None


@dataclass
class VulnMatch:
    """A CVE matched against a detected service."""

    cve: CveRecord
    matched_cpe: str
    confidence: float           # 0.0 - 1.0
    needs_review: bool = False  # true when confidence is below the trust threshold
