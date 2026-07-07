"""Load the local CVE catalog.

MVP reads the curated JSON seed shipped in ``data/cve_seed.json``. The
production path (NVD/OSV sync into SQLite) documented in the development plan
plugs in behind :func:`load_catalog` without changing callers.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from vuln_engine.models import CpeMatch, CveRecord

_SEED_PATH = Path(__file__).parent / "data" / "cve_seed.json"


def _record_from_dict(d: dict) -> CveRecord:
    matches = [
        CpeMatch(
            cpe=m["cpe"],
            version_start=m.get("version_start"),
            version_start_incl=m.get("version_start_incl", False),
            version_end=m.get("version_end"),
            version_end_incl=m.get("version_end_incl", False),
        )
        for m in d.get("matches", [])
    ]
    return CveRecord(
        id=d["id"],
        description=d["description"],
        cvss_v3=d.get("cvss_v3"),
        cvss_vector=d.get("cvss_vector"),
        severity=d.get("severity", "medium"),
        cwe=d.get("cwe"),
        published=d.get("published"),
        references=d.get("references", []),
        matches=matches,
        fixed_version=d.get("fixed_version"),
        recommendation=d.get("recommendation"),
    )


@lru_cache(maxsize=1)
def load_catalog(path: str | None = None) -> list[CveRecord]:
    seed = Path(path) if path else _SEED_PATH
    data = json.loads(seed.read_text(encoding="utf-8"))
    return [_record_from_dict(c) for c in data.get("cves", [])]


def catalog_size(path: str | None = None) -> int:
    return len(load_catalog(path))
