"""Vulnerability findings: list, filter, and triage."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import DbSession, OriginGuard
from backend.app.db.models import Device, Port, Service, Vulnerability
from backend.app.schemas import VulnerabilityUpdate, VulnerabilityView

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"], dependencies=[OriginGuard])

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _view(db: Session, v: Vulnerability) -> VulnerabilityView:
    service = db.get(Service, v.service_id)
    port = db.get(Port, service.port_id) if service else None
    device = db.get(Device, port.device_id) if port else None
    return VulnerabilityView(
        id=v.id, cve_id=v.cve_id, severity=v.cve.severity, cvss_v3=v.cve.cvss_v3,
        description=v.cve.description,
        device_ip=device.ip if device else None,
        port=port.number if port else None,
        product=service.product if service else None,
        version=service.version if service else None,
        match_confidence=v.match_confidence, false_positive=v.false_positive,
        status=v.status, recommendation=v.cve.recommendation, references=v.cve.references or [],
    )


@router.get("", response_model=list[VulnerabilityView])
def list_vulnerabilities(
    db: Session = DbSession,
    scan_id: str = Query(...),
    severity: str | None = None,
    status: str | None = None,
    include_false_positives: bool = False,
) -> list[VulnerabilityView]:
    q = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if status:
        q = q.filter(Vulnerability.status == status)
    if not include_false_positives:
        q = q.filter(Vulnerability.false_positive.is_(False))
    vulns = q.all()
    if severity:
        vulns = [v for v in vulns if v.cve.severity == severity]
    vulns.sort(key=lambda v: (_SEV_ORDER.get(v.cve.severity, 4), -v.match_confidence))
    return [_view(db, v) for v in vulns]


@router.patch("/{vuln_id}", response_model=VulnerabilityView)
def update_vulnerability(
    vuln_id: str, payload: VulnerabilityUpdate, db: Session = DbSession
) -> VulnerabilityView:
    v = db.get(Vulnerability, vuln_id)
    if v is None:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    if payload.false_positive is not None:
        v.false_positive = payload.false_positive
    if payload.status is not None:
        if payload.status not in ("open", "acknowledged", "resolved"):
            raise HTTPException(status_code=400, detail="invalid status")
        v.status = payload.status
    db.commit()
    return _view(db, v)
