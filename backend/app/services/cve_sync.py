"""Upsert the vuln_engine CVE catalog into the local `cves` table.

Vulnerability rows FK to `cves`, so the catalog must exist in the DB. MVP loads
the JSON seed; the production NVD/OSV sync writes to the same table.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app.db.models import Cve
from vuln_engine import load_catalog


def sync_catalog(db: Session) -> int:
    catalog = load_catalog()
    count = 0
    for rec in catalog:
        row = db.get(Cve, rec.id)
        if row is None:
            row = Cve(id=rec.id)
            db.add(row)
        row.description = rec.description
        row.cvss_v3 = rec.cvss_v3
        row.cvss_vector = rec.cvss_vector
        row.severity = rec.severity
        row.cwe = rec.cwe
        row.published = rec.published
        row.references = rec.references
        row.fixed_version = rec.fixed_version
        row.recommendation = rec.recommendation
        count += 1
    db.commit()
    return count
