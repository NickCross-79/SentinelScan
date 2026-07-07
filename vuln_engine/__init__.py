"""SentinelScan vulnerability engine: CVE catalog + service→CVE matching."""

from vuln_engine.database import catalog_size, load_catalog
from vuln_engine.matching import REVIEW_THRESHOLD, match_service, parse_cpe, severity_from_cvss
from vuln_engine.models import CpeMatch, CveRecord, VulnMatch

__all__ = [
    "load_catalog",
    "catalog_size",
    "match_service",
    "parse_cpe",
    "severity_from_cvss",
    "REVIEW_THRESHOLD",
    "CveRecord",
    "CpeMatch",
    "VulnMatch",
]
