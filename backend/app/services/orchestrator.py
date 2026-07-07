"""Scan orchestration: run the engine, persist results, match CVEs, score.

Called by the background job runner. Publishes progress to the ProgressHub so
WebSocket clients see live updates, and writes final results to the DB.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from backend.app.db.base import SessionLocal, utcnow
from backend.app.db.models import (
    Device,
    Port,
    Recommendation,
    Scan,
    Service,
    Vulnerability,
)
from backend.app.services.progress_hub import hub
from backend.app.services.scoring import (
    DeviceFindings,
    ScoreResult,
    score_device,
    score_network,
)
from scanner import ScanEngine
from scanner.engine import ScanProgress
from vuln_engine import match_service

log = logging.getLogger("sentinelscan.orchestrator")


async def run_scan(scan_id: str) -> None:
    """Entry point invoked by the job runner for a single scan."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        job = scan.job if scan else None
        if scan is None or job is None:
            log.error("run_scan: scan %s not found", scan_id)
            return

        scan.status = "running"
        scan.started_at = utcnow()
        job.status = "running"
        db.commit()

        async def on_progress(p: ScanProgress) -> None:
            job.progress = p.percent
            job.current_stage = p.stage
            job.heartbeat_at = utcnow()
            db.commit()
            await hub.publish(
                scan_id,
                {
                    "type": "progress",
                    "scan_id": scan_id,
                    "stage": p.stage,
                    "percent": p.percent,
                    "message": p.message,
                    "host": p.host,
                },
            )

        engine = ScanEngine.from_profile_name(
            scan.profile, custom_ports=scan.options.get("ports")
        )
        result = await engine.run(scan.target, on_progress)

        device_scores = _persist_and_analyze(db, scan, result)

        net = score_network(device_scores)
        scan.score = net.score
        scan.grade = net.grade
        scan.status = "completed"
        scan.finished_at = utcnow()
        job.status = "completed"
        job.progress = 100
        db.commit()

        await hub.publish(
            scan_id,
            {
                "type": "completed",
                "scan_id": scan_id,
                "score": net.score,
                "grade": net.grade,
                "devices": len(result.up_hosts),
            },
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure to the job row
        log.exception("scan %s failed", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.finished_at = utcnow()
            if scan.job:
                scan.job.status = "failed"
                scan.job.error = str(exc)
            db.commit()
        await hub.publish(scan_id, {"type": "failed", "scan_id": scan_id, "error": str(exc)})
    finally:
        db.close()


def _persist_and_analyze(db: Session, scan: Scan, result) -> list[ScoreResult]:
    """Write devices/ports/services, match CVEs, generate recs, score each host."""
    device_scores: list[ScoreResult] = []

    for host in result.up_hosts:
        device = Device(
            scan_id=scan.id,
            ip=host.ip,
            mac=host.mac,
            hostname=host.hostname,
            vendor=host.vendor,
            os_family=host.os_family,
            os_accuracy=host.os_accuracy,
            is_up=True,
        )
        db.add(device)
        db.flush()  # assign device.id

        severities: list[str] = []
        service_names: list[str] = []

        for pr in host.ports:
            port = Port(
                device_id=device.id,
                number=pr.number,
                protocol=pr.protocol,
                state=pr.state,
                reason=pr.reason,
            )
            db.add(port)
            db.flush()

            svc_info = pr.service
            if svc_info is None:
                continue
            service_names.append(svc_info.name)
            service = Service(
                port_id=port.id,
                name=svc_info.name,
                product=svc_info.product,
                version=svc_info.version,
                cpe=svc_info.cpe,
                banner=svc_info.banner,
                extra=svc_info.extra or {},
            )
            db.add(service)
            db.flush()

            for match in match_service(svc_info.cpe):
                vuln = Vulnerability(
                    scan_id=scan.id,
                    service_id=service.id,
                    cve_id=match.cve.id,
                    match_confidence=match.confidence,
                    status="open",
                )
                db.add(vuln)
                db.flush()
                severities.append(match.cve.severity)
                _add_recommendation(db, scan.id, device.id, vuln.id, match.cve)

        findings = DeviceFindings(
            ip=host.ip,
            open_ports=[p.number for p in host.ports],
            service_names=service_names,
            vuln_severities=severities,
        )
        result_score = score_device(findings)
        device.risk_score = result_score.score
        device.grade = result_score.grade
        device.score_factors = result_score.as_dicts()
        device_scores.append(result_score)

    db.commit()
    _add_port_recommendations(db, scan)
    return device_scores


def _add_recommendation(db: Session, scan_id: str, device_id: str, vuln_id: str, cve) -> None:
    priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(cve.severity, 3)
    db.add(
        Recommendation(
            scan_id=scan_id,
            device_id=device_id,
            vulnerability_id=vuln_id,
            category="vulnerability",
            severity=cve.severity,
            title=f"Remediate {cve.id}",
            description=cve.description,
            action=cve.recommendation or "Upgrade the affected software to a fixed version.",
            priority=priority,
        )
    )


def _add_port_recommendations(db: Session, scan: Scan) -> None:
    """Advise on exposed critical ports beyond individual CVEs."""
    from scanner.common_ports import CRITICAL_PORTS

    seen: set[tuple[str, int]] = set()
    for device in scan.devices:
        for port in device.ports:
            if port.number in CRITICAL_PORTS and (device.ip, port.number) not in seen:
                seen.add((device.ip, port.number))
                db.add(
                    Recommendation(
                        scan_id=scan.id,
                        device_id=device.id,
                        category="exposure",
                        severity="high",
                        title=f"Restrict exposed port {port.number} on {device.ip}",
                        description=f"{CRITICAL_PORTS[port.number]} is reachable and is a common attack target.",
                        action="Firewall this port, bind the service to localhost, or require VPN access.",
                        priority=2,
                    )
                )
    db.commit()
