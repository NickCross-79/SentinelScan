"""End-to-end scan through the real API using FastAPI's TestClient.

Spins up a fake Apache/2.4.49 service, drives a scan via REST, and asserts the
full loop persists devices, matches CVEs, scores, and generates a report.
"""

import http.server
import socketserver
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


class _FakeApache(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def fake_service():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _FakeApache)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # triggers lifespan: db init, catalog sync, runner
        yield c


def _wait_for_completion(client, scan_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/scans/{scan_id}").json()
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(0.3)
    raise AssertionError("scan did not complete in time")


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_authorization_gate_rejected(client):
    r = client.post("/api/scans/start", json={"target": "127.0.0.1", "authorized": False})
    assert r.status_code == 400


def test_full_scan_finds_apache_cve(client, fake_service):
    r = client.post(
        "/api/scans/start",
        json={
            "target": "127.0.0.1",
            "profile": "custom",
            "authorized": True,
            "options": {"ports": [fake_service, 65500]},
        },
    )
    assert r.status_code == 201
    scan_id = r.json()["scan_id"]

    summary = _wait_for_completion(client, scan_id)
    assert summary["status"] == "completed"
    assert summary["device_count"] == 1
    assert summary["critical_count"] >= 1
    assert summary["score"] is not None

    vulns = client.get(f"/api/vulnerabilities?scan_id={scan_id}").json()
    cve_ids = {v["cve_id"] for v in vulns}
    assert "CVE-2021-42013" in cve_ids
    assert "CVE-2021-41773" in cve_ids

    # Report generation + download.
    rep = client.post("/api/reports", json={"scan_id": scan_id, "format": "html"})
    assert rep.status_code == 201
    dl = client.get(rep.json()["download_url"])
    assert dl.status_code == 200
    assert "SentinelScan" in dl.text


def test_websocket_stream_delivers_events(client, fake_service):
    """Regression: the WS route must not inherit the HTTP-only origin guard."""
    r = client.post(
        "/api/scans/start",
        json={"target": "127.0.0.1", "profile": "custom", "authorized": True,
              "options": {"ports": [fake_service]}},
    )
    scan_id = r.json()["scan_id"]
    saw_terminal = False
    with client.websocket_connect(f"/api/scans/{scan_id}/stream") as ws:
        for _ in range(50):
            event = ws.receive_json()
            assert event["scan_id"] == scan_id
            if event["type"] in ("completed", "failed"):
                saw_terminal = True
                break
    assert saw_terminal, "WebSocket did not deliver a terminal scan event"


def test_false_positive_triage(client, fake_service):
    r = client.post(
        "/api/scans/start",
        json={"target": "127.0.0.1", "profile": "custom", "authorized": True,
              "options": {"ports": [fake_service]}},
    )
    scan_id = r.json()["scan_id"]
    _wait_for_completion(client, scan_id)
    vulns = client.get(f"/api/vulnerabilities?scan_id={scan_id}").json()
    vid = vulns[0]["id"]
    client.patch(f"/api/vulnerabilities/{vid}", json={"false_positive": True})
    remaining = client.get(f"/api/vulnerabilities?scan_id={scan_id}").json()
    assert vid not in {v["id"] for v in remaining}
