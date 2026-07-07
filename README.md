# 🛡️ SentinelScan

**A local-first network security scanner.** Discover devices on a network you own,
enumerate their services, match detected software versions against CVE databases,
get an explainable 0–100 security score, and generate reports — all running locally,
at **$0/month** infrastructure cost.

> ⚠️ **Authorized use only.** Scan networks you own or have explicit permission to
> test. Unauthorized scanning may be illegal. SentinelScan enforces an
> authorization gate and blocks public IP ranges by default.

This repository contains a working **MVP** (Phases 0–3 of the
[development plan](docs/DEVELOPMENT_PLAN.md)): the full scan → score → CVE-match →
report loop, with a polished React dashboard and live scan progress.

---

## What works today

- **Device discovery** — privilege-free TCP-ping host discovery + reverse DNS (no root, no nmap required).
- **Port scanning** — async TCP connect scanning with `quick` / `full` / `custom` profiles.
- **Service & version detection** — banner grabbing + HTTP probing, normalized to CPEs.
- **Vulnerability matching** — offline CVE catalog with CPE + version-range matching and confidence scoring.
- **Explainable security scoring** — 0–100 score + A–F grade with a per-device "why this score" breakdown.
- **Recommendations** — prioritized, plain-language remediation for every finding.
- **Reports** — JSON / CSV / print-ready HTML export.
- **Dashboard** — React + TypeScript + Tailwind SPA with live WebSocket scan progress.

The canonical demo: an **Apache httpd 2.4.49** service is detected and matched to
**CVE-2021-42013** (Critical, CVSS 9.8) and **CVE-2021-41773** (High), each with a
remediation action.

---

## Quickstart (native)

Requires **Python 3.11+** and **Node 22+**.

```bash
# 1. Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Frontend (build once so the backend can serve it)
cd frontend && npm install && npm run build && cd ..

# 3. Run — serves API + dashboard at http://127.0.0.1:8787
sentinelscan
```

Open **http://127.0.0.1:8787**, go to **Scan**, enter `127.0.0.1` (or your subnet like
`192.168.1.0/24`), tick the authorization box, and start.

### Frontend dev mode (hot reload)

```bash
# Terminal 1: backend
sentinelscan
# Terminal 2: Vite dev server with API/WS proxy → http://localhost:5173
cd frontend && npm run dev
```

## Quickstart (Docker)

```bash
docker compose -f docker/docker-compose.yml up --build
# → http://localhost:8787
```

> Containers only see the container network. To scan your LAN, use the native
> install or add `network_mode: host` (Linux) in the compose file.

---

## Testing

```bash
source .venv/bin/activate
pytest                 # backend unit + integration tests (spins up a real scan)
cd frontend && npm run build   # type-checks the frontend (tsc strict)
```

---

## Architecture (MVP)

```
React SPA ──REST/JSON──▶ FastAPI (127.0.0.1) ──▶ asyncio job runner ──▶ scan engine
         ◀─WebSocket───   progress hub            (SQLite job table)      (scanner/)
                                │                                              │
                                ▼                                              ▼
                          SQLAlchemy / SQLite   ◀── vuln engine (CVE match) ── services/versions
```

- **`scanner/`** — framework-free scanning engine (discovery, ports, fingerprinting). Usable as a library.
- **`vuln_engine/`** — offline CVE catalog + CPE/version-range matching.
- **`backend/`** — FastAPI app, ORM models, scan orchestration, scoring, reports, background runner.
- **`frontend/`** — React/TS/Tailwind dashboard.

Background scans run in an **in-process asyncio runner** backed by a SQLite
`scan_jobs` table — no Redis or broker, which is what keeps running cost at $0.
See [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) for the full design,
database schema, API reference, roadmap, and security analysis.

---

## Configuration

Environment variables (prefix `SENTINEL_`), e.g. `SENTINEL_PORT=9000`:

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in Docker) |
| `SENTINEL_PORT` | `8787` | HTTP port |
| `SENTINEL_DATA_DIR` | `~/.sentinelscan` | SQLite DB + reports location |
| `SENTINEL_ALLOW_PUBLIC_TARGETS` | `false` | Permit scanning non-private ranges |
| `SENTINEL_MAX_CONCURRENT_SCANS` | `2` | Parallel scan cap |

---

## Roadmap

Implemented: Phases 0–3 (setup, MVP scanner, dashboard, vulnerability engine) plus
report generation. Not yet built (see the plan): nmap `-O`/SYN backend, TLS/SSL
analysis, live NVD/OSV sync, PDF reports, network-map graph, scheduled scans, and
Tauri desktop packaging.

## License

Apache-2.0 — see [LICENSE](LICENSE).
