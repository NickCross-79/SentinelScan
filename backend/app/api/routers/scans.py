"""Scan lifecycle + live progress WebSocket."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.api.deps import DbSession, OriginGuard
from backend.app.config import settings
from backend.app.core.security import TargetValidationError, validate_target
from backend.app.db.models import Device, Scan, ScanJob, Vulnerability
from backend.app.schemas import JobView, ScanCreate, ScanCreated, ScanSummary
from backend.app.services.progress_hub import hub

# OriginGuard is applied per HTTP route (not router-wide) so it is not injected
# into the WebSocket route, which has no HTTP Request to satisfy the dependency.
router = APIRouter(prefix="/api/scans", tags=["scans"])


def _summary(db: Session, scan: Scan) -> ScanSummary:
    device_count = db.query(func.count(Device.id)).filter(Device.scan_id == scan.id).scalar() or 0
    vuln_q = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan.id, Vulnerability.false_positive.is_(False)
    )
    vuln_count = vuln_q.count()
    critical = sum(1 for v in vuln_q.all() if v.cve.severity == "critical")
    job = scan.job
    return ScanSummary(
        id=scan.id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        score=scan.score,
        grade=scan.grade,
        device_count=device_count,
        vuln_count=vuln_count,
        critical_count=critical,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
        job=JobView(
            status=job.status, progress=job.progress,
            current_stage=job.current_stage, error=job.error,
        ) if job else None,
    )


@router.post("/start", response_model=ScanCreated, status_code=201, dependencies=[OriginGuard])
def start_scan(payload: ScanCreate, db: Session = DbSession) -> ScanCreated:
    try:
        target = validate_target(payload.target, payload.authorized)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if payload.profile not in ("quick", "full", "custom"):
        raise HTTPException(status_code=400, detail="invalid profile")

    scan = Scan(target=target, profile=payload.profile, options=payload.options or {}, status="queued")
    db.add(scan)
    db.flush()
    db.add(ScanJob(scan_id=scan.id, status="queued", progress=0))
    db.commit()
    return ScanCreated(scan_id=scan.id, status="queued")


@router.get("", response_model=list[ScanSummary], dependencies=[OriginGuard])
def list_scans(
    db: Session = DbSession,
    limit: int = Query(50, le=200),
    offset: int = 0,
    status: str | None = None,
) -> list[ScanSummary]:
    q = db.query(Scan).order_by(Scan.created_at.desc())
    if status:
        q = q.filter(Scan.status == status)
    return [_summary(db, s) for s in q.offset(offset).limit(limit).all()]


@router.get("/{scan_id}", response_model=ScanSummary, dependencies=[OriginGuard])
def get_scan(scan_id: str, db: Session = DbSession) -> ScanSummary:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return _summary(db, scan)


@router.post("/{scan_id}/cancel", response_model=ScanSummary, dependencies=[OriginGuard])
def cancel_scan(scan_id: str, db: Session = DbSession) -> ScanSummary:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.status in ("queued", "running", "claimed"):
        scan.status = "cancelled"
        if scan.job:
            scan.job.status = "cancelled"
        db.commit()
    return _summary(db, scan)


@router.websocket("/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str) -> None:
    # Manual origin guard for the WebSocket handshake (mirrors OriginGuard).
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in settings.allowed_origins:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    queue = hub.subscribe(scan_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                await websocket.send_json(event)
                if event.get("type") in ("completed", "failed"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "scan_id": scan_id})
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(scan_id, queue)
