"""Report generation and download."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.api.deps import DbSession, OriginGuard
from backend.app.config import settings
from backend.app.db.models import Report, Scan
from backend.app.schemas import ReportCreate, ReportView
from backend.app.services.reports import generate_report

router = APIRouter(prefix="/api/reports", tags=["reports"], dependencies=[OriginGuard])

_MEDIA = {"json": "application/json", "html": "text/html", "csv": "text/csv"}


def _view(r: Report) -> ReportView:
    return ReportView(
        id=r.id, scan_id=r.scan_id, format=r.format,
        created_at=r.created_at, summary=r.summary or {},
        download_url=f"/api/reports/{r.id}/download",
    )


@router.post("", response_model=ReportView, status_code=201)
def create_report(payload: ReportCreate, db: Session = DbSession) -> ReportView:
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="scan is not completed")
    try:
        report = generate_report(db, scan, payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _view(report)


@router.get("/{report_id}", response_model=ReportView)
def get_report(report_id: str, db: Session = DbSession) -> ReportView:
    r = db.get(Report, report_id)
    if r is None:
        raise HTTPException(status_code=404, detail="report not found")
    return _view(r)


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = DbSession) -> FileResponse:
    r = db.get(Report, report_id)
    if r is None or not r.file_path:
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(r.file_path).resolve()
    # Path-traversal guard: file must live under the reports dir.
    reports_root = settings.reports_dir.resolve()
    if reports_root not in path.parents:
        raise HTTPException(status_code=403, detail="invalid report path")
    if not path.exists():
        raise HTTPException(status_code=404, detail="report file missing")
    return FileResponse(
        path, media_type=_MEDIA.get(r.format, "application/octet-stream"),
        filename=f"sentinelscan-{r.scan_id[:8]}.{r.format}",
    )
