"""Report generation: JSON, CSV, and self-contained HTML.

PDF is intentionally deferred (WeasyPrint/headless-Chromium) per the plan; the
HTML report is print-ready in the browser in the meantime. All scan-derived
text is HTML-escaped to prevent stored-XSS via banners/hostnames.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db.models import Report, Scan


def build_summary(db: Session, scan: Scan) -> dict:
    devices = scan.devices
    vulns = [v for v in scan.vulnerabilities if not v.false_positive]
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev_counts[v.cve.severity] = sev_counts.get(v.cve.severity, 0) + 1

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "profile": scan.profile,
        "score": scan.score,
        "grade": scan.grade,
        "status": scan.status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "vulnerability_count": len(vulns),
        "severity_counts": sev_counts,
        "devices": [
            {
                "ip": d.ip,
                "hostname": d.hostname,
                "os_family": d.os_family,
                "risk_score": d.risk_score,
                "grade": d.grade,
                "open_ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "service": (p.service.name if p.service else None),
                        "product": (p.service.product if p.service else None),
                        "version": (p.service.version if p.service else None),
                    }
                    for p in d.ports
                ],
            }
            for d in devices
        ],
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "severity": v.cve.severity,
                "cvss_v3": v.cve.cvss_v3,
                "description": v.cve.description,
                "recommendation": v.cve.recommendation,
                "confidence": v.match_confidence,
            }
            for v in vulns
        ],
        "recommendations": [
            {
                "title": r.title,
                "severity": r.severity,
                "action": r.action,
                "priority": r.priority,
            }
            for r in sorted(scan.recommendations, key=lambda r: r.priority)
        ],
    }


def _render_json(summary: dict) -> str:
    return json.dumps(summary, indent=2, default=str)


def _render_csv(summary: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["CVE", "Severity", "CVSS", "Description", "Recommendation"])
    for v in summary["vulnerabilities"]:
        w.writerow([v["cve_id"], v["severity"], v["cvss_v3"], v["description"], v["recommendation"]])
    return buf.getvalue()


def _render_html(summary: dict) -> str:
    e = html.escape
    sc = summary["severity_counts"]
    rows = []
    for v in summary["vulnerabilities"]:
        rows.append(
            f"<tr class='sev-{e(v['severity'])}'><td>{e(v['cve_id'])}</td>"
            f"<td>{e(v['severity'])}</td><td>{e(str(v['cvss_v3']))}</td>"
            f"<td>{e(v['description'])}</td><td>{e(str(v['recommendation']))}</td></tr>"
        )
    device_rows = []
    for d in summary["devices"]:
        ports = ", ".join(str(p["number"]) for p in d["open_ports"]) or "none"
        device_rows.append(
            f"<tr><td>{e(d['ip'])}</td><td>{e(str(d['hostname']))}</td>"
            f"<td>{e(str(d['os_family']))}</td><td>{e(str(d['risk_score']))} ({e(str(d['grade']))})</td>"
            f"<td>{e(ports)}</td></tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>SentinelScan Report — {e(summary['target'])}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#111;max-width:1000px}}
h1{{margin-bottom:0}} .muted{{color:#666}}
.score{{font-size:3rem;font-weight:700}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem}}
th{{background:#f3f4f6}}
.sev-critical{{background:#fde8e8}} .sev-high{{background:#fef3e2}}
.sev-medium{{background:#fefce8}} .sev-low{{background:#f0fdf4}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:.4rem;background:#eef}}
</style></head><body>
<h1>SentinelScan Security Report</h1>
<p class="muted">Target <strong>{e(summary['target'])}</strong> · generated {e(summary['generated_at'])}</p>
<p class="score">{e(str(summary['score']))}<span class="muted"> / 100 · grade {e(str(summary['grade']))}</span></p>
<p><span class="badge">{summary['device_count']} devices</span>
<span class="badge">{sc['critical']} critical</span>
<span class="badge">{sc['high']} high</span>
<span class="badge">{sc['medium']} medium</span>
<span class="badge">{sc['low']} low</span></p>
<h2>Devices</h2>
<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Risk</th><th>Open ports</th></tr>
{''.join(device_rows) or '<tr><td colspan=5>No devices</td></tr>'}</table>
<h2>Vulnerabilities</h2>
<table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th><th>Recommendation</th></tr>
{''.join(rows) or '<tr><td colspan=5>No vulnerabilities detected</td></tr>'}</table>
<p class="muted">SentinelScan — local-first network security scanner. Results contain sensitive
reconnaissance data; store and share with care.</p>
</body></html>"""


_RENDERERS = {
    "json": (_render_json, "json"),
    "csv": (_render_csv, "csv"),
    "html": (_render_html, "html"),
}


def generate_report(db: Session, scan: Scan, fmt: str) -> Report:
    if fmt not in _RENDERERS:
        raise ValueError(f"unsupported format: {fmt}")
    summary = build_summary(db, scan)
    render, ext = _RENDERERS[fmt]
    content = render(summary)

    report = Report(scan_id=scan.id, format=fmt, summary={
        "score": summary["score"],
        "grade": summary["grade"],
        "device_count": summary["device_count"],
        "vulnerability_count": summary["vulnerability_count"],
        "severity_counts": summary["severity_counts"],
    })
    db.add(report)
    db.flush()  # assign report.id for the filename

    path = settings.reports_dir / f"{report.id}.{ext}"
    path.write_text(content, encoding="utf-8")
    report.file_path = str(path)
    db.commit()
    return report
