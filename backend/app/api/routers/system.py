"""System, health, recommendations, and CVE-catalog endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import DbSession, OriginGuard
from backend.app.db.models import Cve, Device, Recommendation
from backend.app.schemas import RecommendationView
from vuln_engine import catalog_size

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "sentinelscan"}


@router.get("/cve/status", dependencies=[OriginGuard])
def cve_status(db: Session = DbSession) -> dict:
    db_count = db.query(Cve).count()
    return {"catalog_seed": catalog_size(), "catalog_db": db_count, "source": "offline-seed"}


@router.get("/recommendations", response_model=list[RecommendationView], dependencies=[OriginGuard])
def list_recommendations(scan_id: str = Query(...), db: Session = DbSession) -> list[RecommendationView]:
    recs = (
        db.query(Recommendation)
        .filter(Recommendation.scan_id == scan_id)
        .order_by(Recommendation.priority)
        .all()
    )
    out: list[RecommendationView] = []
    for r in recs:
        device = db.get(Device, r.device_id) if r.device_id else None
        out.append(
            RecommendationView(
                id=r.id, category=r.category, severity=r.severity, title=r.title,
                description=r.description, action=r.action, priority=r.priority,
                device_ip=device.ip if device else None,
            )
        )
    return out
