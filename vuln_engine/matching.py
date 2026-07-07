"""Match detected services against the CVE catalog.

Algorithm (see docs/DEVELOPMENT_PLAN.md §7):
  1. Parse the service CPE into (vendor, product, version).
  2. Collect catalog CVEs whose match rules target the same vendor:product.
  3. Test the detected version against each rule's version range.
  4. Emit a VulnMatch with a confidence score; low-confidence hits are flagged
     ``needs_review`` rather than asserted.
"""

from __future__ import annotations

from vuln_engine.database import load_catalog
from vuln_engine.models import CveRecord, VulnMatch
from vuln_engine.versions import in_range

# Below this confidence a finding is "potential" (needs human review).
REVIEW_THRESHOLD = 0.5


def parse_cpe(cpe: str | None) -> tuple[str, str, str | None] | None:
    """Return (vendor, product, version) from a cpe:2.3 string, or None."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    # cpe:2.3:a:vendor:product[:version...]
    if len(parts) < 5:
        return None
    vendor, product = parts[3], parts[4]
    version = parts[5] if len(parts) > 5 and parts[5] not in ("", "*", "-") else None
    return vendor, product, version


def _rule_vendor_product(cpe: str) -> tuple[str, str] | None:
    parsed = parse_cpe(cpe if cpe.count(":") >= 4 else None)
    if parsed:
        return parsed[0], parsed[1]
    # Rule CPEs may omit the version entirely: cpe:2.3:a:vendor:product
    parts = cpe.split(":")
    if len(parts) >= 5:
        return parts[3], parts[4]
    return None


def match_service(cpe: str | None, catalog: list[CveRecord] | None = None) -> list[VulnMatch]:
    """Return CVE matches for a single service CPE, sorted by severity/confidence."""
    parsed = parse_cpe(cpe)
    if parsed is None:
        return []
    vendor, product, version = parsed
    catalog = catalog if catalog is not None else load_catalog()

    results: list[VulnMatch] = []
    for cve in catalog:
        for rule in cve.matches:
            vp = _rule_vendor_product(rule.cpe)
            if vp != (vendor, product):
                continue

            if version is None:
                # Product matches but we have no version — potential only.
                results.append(
                    VulnMatch(cve=cve, matched_cpe=rule.cpe, confidence=0.4, needs_review=True)
                )
                break

            if in_range(
                version,
                rule.version_start,
                rule.version_start_incl,
                rule.version_end,
                rule.version_end_incl,
            ):
                bounded = rule.version_start is not None and rule.version_end is not None
                confidence = 0.95 if bounded else 0.8
                results.append(
                    VulnMatch(
                        cve=cve,
                        matched_cpe=rule.cpe,
                        confidence=confidence,
                        needs_review=confidence < REVIEW_THRESHOLD,
                    )
                )
                break  # one match per CVE is enough

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda m: (_SEV_ORDER.get(m.cve.severity, 4), -m.confidence))
    return results


def severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
