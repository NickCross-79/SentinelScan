"""Device listing and detail."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import DbSession, OriginGuard
from backend.app.db.models import Device
from backend.app.schemas import DeviceDetail, DeviceSummary, PortView, ServiceView

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[OriginGuard])


def _summary(d: Device) -> DeviceSummary:
    return DeviceSummary(
        id=d.id, ip=d.ip, hostname=d.hostname, vendor=d.vendor,
        os_family=d.os_family, risk_score=d.risk_score, grade=d.grade,
        open_ports=len(d.ports),
    )


@router.get("", response_model=list[DeviceSummary])
def list_devices(scan_id: str = Query(...), db: Session = DbSession) -> list[DeviceSummary]:
    devices = db.query(Device).filter(Device.scan_id == scan_id).order_by(Device.ip).all()
    return [_summary(d) for d in devices]


@router.get("/{device_id}", response_model=DeviceDetail)
def get_device(device_id: str, db: Session = DbSession) -> DeviceDetail:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status_code=404, detail="device not found")
    ports = [
        PortView(
            number=p.number, protocol=p.protocol, state=p.state,
            service=ServiceView(
                name=p.service.name, product=p.service.product,
                version=p.service.version, cpe=p.service.cpe, banner=p.service.banner,
            ) if p.service else None,
        )
        for p in sorted(d.ports, key=lambda p: p.number)
    ]
    return DeviceDetail(
        **_summary(d).model_dump(),
        mac=d.mac, os_accuracy=d.os_accuracy,
        score_factors=d.score_factors or [], ports=ports,
    )
