"""Deterministic scoring behaviour."""

from backend.app.services.scoring import (
    DeviceFindings,
    grade_for,
    score_device,
    score_network,
)


def test_clean_device_scores_full():
    r = score_device(DeviceFindings(ip="10.0.0.1", open_ports=[443], service_names=["https"]))
    assert r.score == 100
    assert r.grade == "A"


def test_critical_vuln_penalized():
    r = score_device(
        DeviceFindings(ip="10.0.0.2", open_ports=[80], vuln_severities=["critical"])
    )
    assert r.score == 75  # 100 - 25
    assert any(f.factor == "critical_vulnerabilities" for f in r.factors)


def test_penalty_caps_prevent_negative_scores():
    r = score_device(
        DeviceFindings(ip="10.0.0.3", vuln_severities=["critical"] * 10)
    )
    assert r.score == 40  # cap of 60 on critical band → 100 - 60
    assert r.score >= 0


def test_exposed_critical_port_penalty():
    r = score_device(DeviceFindings(ip="10.0.0.4", open_ports=[3389]))
    assert r.score < 100
    assert any(f.factor == "exposed_critical_ports" for f in r.factors)


def test_network_weights_toward_worst_host():
    good = score_device(DeviceFindings(ip="a", open_ports=[443]))
    bad = score_device(DeviceFindings(ip="b", vuln_severities=["critical", "critical"]))
    net = score_network([good, bad])
    mean = (good.score + bad.score) / 2
    # Worst host drags the network score below the plain mean.
    assert net.score < mean


def test_grade_boundaries():
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(59) == "F"
