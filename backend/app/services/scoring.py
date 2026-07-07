"""Deterministic, explainable security scoring (docs/DEVELOPMENT_PLAN.md §8).

Start at 100, subtract capped weighted penalties, floor at 0. Every score keeps
the list of contributing factors so the UI can show "why this score".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.common_ports import CRITICAL_PORTS

# Per-occurrence penalties and per-factor caps.
PENALTY = {
    "critical": 25,
    "high": 12,
    "medium": 5,
    "low": 1,
    "critical_port": 10,
    "cleartext_service": 6,
}
CAP = {
    "critical": 60,
    "high": 48,
    "medium": 30,
    "critical_port": 30,
    "cleartext_service": 18,
}

CLEARTEXT_SERVICES = {"telnet", "ftp"}


@dataclass
class Factor:
    factor: str
    weight: int
    evidence: str


@dataclass
class ScoreResult:
    score: int
    grade: str
    factors: list[Factor] = field(default_factory=list)

    def as_dicts(self) -> list[dict]:
        return [f.__dict__ for f in self.factors]


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


@dataclass
class DeviceFindings:
    """Minimal, framework-free view of a device used for scoring."""

    ip: str
    open_ports: list[int] = field(default_factory=list)
    service_names: list[str] = field(default_factory=list)
    vuln_severities: list[str] = field(default_factory=list)  # excludes false positives


def score_device(findings: DeviceFindings) -> ScoreResult:
    factors: list[Factor] = []
    score = 100

    # 1. Vulnerabilities by severity (capped per band).
    for band in ("critical", "high", "medium", "low"):
        count = sum(1 for s in findings.vuln_severities if s == band)
        if not count:
            continue
        raw = PENALTY[band] * count
        weight = min(raw, CAP.get(band, raw))
        score -= weight
        factors.append(Factor(f"{band}_vulnerabilities", weight, f"{count} {band} CVE(s)"))

    # 2. Exposed critical ports.
    crit = [p for p in findings.open_ports if p in CRITICAL_PORTS]
    if crit:
        weight = min(PENALTY["critical_port"] * len(crit), CAP["critical_port"])
        score -= weight
        evidence = ", ".join(f"{p} ({CRITICAL_PORTS[p]})" for p in crit)
        factors.append(Factor("exposed_critical_ports", weight, evidence))

    # 3. Cleartext services.
    cleartext = [s for s in findings.service_names if s in CLEARTEXT_SERVICES]
    if cleartext:
        weight = min(PENALTY["cleartext_service"] * len(cleartext), CAP["cleartext_service"])
        score -= weight
        factors.append(
            Factor("cleartext_services", weight, ", ".join(sorted(set(cleartext))))
        )

    score = max(0, min(100, score))
    return ScoreResult(score=score, grade=grade_for(score), factors=factors)


def score_network(device_results: list[ScoreResult]) -> ScoreResult:
    """Severity-weighted aggregate: worst devices dominate, so one bad host is
    not hidden behind many healthy ones."""
    if not device_results:
        return ScoreResult(score=100, grade="A", factors=[])

    scores = [d.score for d in device_results]
    mean = sum(scores) / len(scores)
    worst = min(scores)
    # Pull the mean toward the worst host (70/30 blend).
    network = int(round(0.7 * mean + 0.3 * worst))
    network = max(0, min(100, network))

    factors = [
        Factor("device_count", len(device_results), f"{len(device_results)} host(s) scored"),
        Factor("worst_device", worst, "lowest-scoring host"),
        Factor("mean_device", int(round(mean)), "average host score"),
    ]
    return ScoreResult(score=network, grade=grade_for(network), factors=factors)
