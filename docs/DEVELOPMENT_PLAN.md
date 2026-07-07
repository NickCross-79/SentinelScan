# SentinelScan — Technical Development Plan

## Context

**Why this exists:** This document is the complete, implementation-ready technical design for **SentinelScan** — a local-first, $0/month-infrastructure network security scanner — written so a developer can pick it up and start building immediately. It is the single source of truth for architecture, scope, schema, APIs, roadmap, and risk decisions. No application code is written yet; this plan comes first.

**Guiding constraints (from the brief):**
- Local-first, privacy-preserving, $0/month running cost (no paid SaaS, no mandatory cloud).
- Professional-grade output usable by home users, students, developers, and small businesses.
- Prioritize security, privacy, local execution, extensibility, and developer experience.
- **Do not over-engineer v1.** Ship a working scanner + polished dashboard before enterprise features.

---

## Recommended Stack (decisions up front)

| Layer | Choice | Why |
|---|---|---|
| Frontend | **React + TypeScript + Tailwind + Vite** | Mature ecosystem, type safety catches bugs in a data-heavy dashboard, Tailwind gives a polished UI fast without a design system. |
| Desktop packaging | **Tauri (via sidecar)** — Phase 5, optional | ~10× smaller than Electron, Rust core is memory-safe, ships a hardened webview. Python backend runs as a Tauri *sidecar* process. Browser-served SPA is the default; desktop bundle is additive. |
| Backend | **Python 3.11+ + FastAPI + Uvicorn** | Python owns the security-tooling ecosystem (Scapy, python-nmap, sslyze). FastAPI gives async I/O, automatic OpenAPI docs, and Pydantic validation for free. |
| Async / workers | **asyncio + a SQLite-backed job table** (MVP); ARQ+Redis optional later | Scans are long-running and I/O-bound. An in-process background task runner with a persisted `scan_jobs` table needs **zero extra infrastructure** — no Redis, no broker — which is required for the $0 goal. |
| Database | **SQLite (default) via SQLAlchemy 2.0 + Alembic**; PostgreSQL optional | SQLite is a single file, zero-admin, perfect for local-first. SQLAlchemy keeps the code portable so Postgres is a config switch, not a rewrite. Alembic manages migrations. |
| Scanning libs | **python-nmap / nmap CLI, Scapy, sslyze, cryptography (OpenSSL)** | Nmap is the industry standard for port/service/OS detection; Scapy for raw ARP/ICMP; sslyze for TLS analysis; `cryptography` for cert parsing. All open-source, all local. |
| Vuln data | **OSV.dev API + local offline mirror; NVD JSON feeds; optional Trivy** | OSV is free, no API key, great for package CVEs. NVD feeds give a local CVE mirror (offline-capable). Trivy is an optional local binary for deeper checks. No paid CVE feed. |
| Deployment | **Docker Compose + native local install** | One-command local run; Docker for reproducibility. Cloud is explicitly out of scope for v1. |

**Key architectural decision — packaging:** The backend is a **local HTTP service** (FastAPI on `127.0.0.1`), and the frontend is a static SPA that talks to it. This one design serves all three delivery modes: (a) `docker compose up`, (b) native `pip install` + `npm run dev`, and (c) Tauri desktop bundle (sidecar-launches the same FastAPI binary). No architecture fork between web and desktop.

---

## Section 1 — Executive Overview

**What it does.** SentinelScan discovers devices on a network you own, enumerates their open ports and running services, fingerprints operating systems, checks web/TLS hygiene, matches detected software versions against CVE databases, computes a 0–100 risk score, and generates plain-language reports with prioritized remediation steps — all running locally.

**Who it's for.**
- **Home users** who want a readable answer to "is my network safe?" without learning nmap flags.
- **Students** learning offensive/defensive security in a lab, with an inspectable open-source codebase.
- **Developers** hardening their own dev/staging environments.
- **Small businesses** needing a basic, defensible self-assessment without a Nessus license.

**Why it's valuable.** Existing tools force a trade-off: raw power with a steep CLI (Nmap), or a polished UI locked behind cost and complexity (Nessus, Qualys). SentinelScan pairs a real scanning engine with an approachable dashboard, prioritized findings, and human-readable remediation — at $0.

**Differentiation.**
| Tool | Gap SentinelScan fills |
|---|---|
| **Nmap** | Powerful but CLI-only, no persistence, no CVE correlation, no risk score, no report. SentinelScan *uses* nmap and adds the product layer on top. |
| **Nessus / Qualys** | Commercial, licensed, cloud-tied, heavyweight. SentinelScan is free, local-first, privacy-preserving. |
| **OpenVAS/GVM** | Free but notoriously hard to install and operate. SentinelScan targets one-command setup and a modern UX. |
| **Trivy** | Excellent for container/package scanning but not network discovery. SentinelScan can *integrate* Trivy while owning the network-topology story. |

**The wedge:** "The security posture of your whole network, explained like a report card, running entirely on your own machine."

---

## Section 2 — Feature Breakdown

Each feature: *Description · Technical requirements · Difficulty · Dependencies · Security considerations · MVP priority.* Difficulty is S/M/L/XL. MVP priority is **P0 (MVP), P1 (fast-follow), P2 (advanced), P3 (future).**

### Core MVP Features (P0)

**F1. Network device discovery**
- *Description:* Find live hosts on a subnet; resolve IP, MAC, hostname, vendor.
- *Requirements:* ARP scan (Scapy or `nmap -sn`), ICMP echo, reverse-DNS, MAC→vendor via local IEEE OUI database.
- *Difficulty:* M. *Dependencies:* Scapy/nmap, OUI file, raw-socket privileges.
- *Security:* Raw sockets need elevated privileges — isolate in a privileged helper; validate/normalize CIDR input; restrict to RFC1918 + user-confirmed ranges.
- *MVP:* **P0.**

**F2. Port scanning**
- *Description:* TCP connect + SYN scans, UDP scan for common ports, per-port state.
- *Requirements:* nmap engine wrapper (`-sT`, `-sS`, `-sU`), configurable port ranges, concurrency/rate limits.
- *Difficulty:* M. *Dependencies:* nmap, F1.
- *Security:* Rate-limit to avoid self-DoS; SYN scan needs root; enforce authorization gate before any scan.
- *MVP:* **P0.**

**F3. Service & version detection**
- *Description:* Identify service + version behind each open port (banner grabbing + nmap `-sV`).
- *Requirements:* nmap service probes, banner capture, protocol parsers.
- *Difficulty:* M. *Dependencies:* F2.
- *Security:* Banner grabbing sends bytes to services — bound read sizes, sanitize banners before storage/render (XSS in report).
- *MVP:* **P0.**

**F4. OS fingerprinting**
- *Description:* Best-guess OS family/version.
- *Requirements:* nmap `-O` TCP/IP fingerprinting; TTL heuristics as fallback.
- *Difficulty:* M. *Dependencies:* F2, root.
- *Security:* Report as probabilistic, never asserted fact.
- *MVP:* **P0 (basic).**

**F5. Security scoring (basic)**
- *Description:* 0–100 network + per-device score from weighted findings.
- *Requirements:* Deterministic scoring engine (Section 8).
- *Difficulty:* M. *Dependencies:* F1–F4.
- *Security:* Score must be explainable/auditable — store factor breakdown, not just the number.
- *MVP:* **P0.**

**F6. Dashboard & scan control**
- *Description:* Start/monitor scans, view devices, see score and top findings.
- *Requirements:* React SPA, live progress (WebSocket/SSE), REST API.
- *Difficulty:* L. *Dependencies:* backend API.
- *Security:* Local-only binding; CSRF/localhost-origin checks; sanitize all rendered scan data.
- *MVP:* **P0.**

**F7. Scan persistence & history**
- *Description:* Store scans, diff over time.
- *Requirements:* SQLite schema (Section 4), SQLAlchemy models.
- *Difficulty:* M. *Dependencies:* DB.
- *Security:* Results are sensitive recon data — see Section 12 (at-rest protection, file permissions).
- *MVP:* **P0.**

### Advanced Features (P1–P2)

**F8. Vulnerability scanner (CVE matching)** — *P1*
- *Description:* Map service+version → CVEs with severity + remediation.
- *Requirements:* OSV API + local NVD mirror, CPE/version-range matching engine (Section 7), severity from CVSS.
- *Difficulty:* XL. *Dependencies:* F3, CVE data pipeline.
- *Security:* False-positive handling critical; never auto-exploit; cache CVE data locally for offline + privacy.

**F9. Web security checks** — *P1*
- *Description:* For HTTP(S) services: missing security headers (HSTS, CSP, X-Frame-Options), directory listing, default pages, cookie flags.
- *Requirements:* async HTTP client (httpx), header/response analyzers.
- *Difficulty:* M. *Dependencies:* F3.
- *Security:* Passive checks only in MVP — no injection/fuzzing; respect scope gate; bound redirects.

**F10. TLS/SSL analysis** — *P1*
- *Description:* Protocol versions, cipher strength, cert validity/expiry, chain issues, weak/deprecated config.
- *Requirements:* sslyze + `cryptography` for cert parsing.
- *Difficulty:* M. *Dependencies:* F3.
- *Security:* Handshake-only, no exploitation.

**F11. Remediation & recommendations** — *P1*
- *Description:* Actionable, plain-language fixes tied to findings.
- *Requirements:* rules/knowledge base mapping finding→advice; templated remediation text.
- *Difficulty:* M. *Dependencies:* F8–F10.

**F12. Report generation** — *P1*
- *Description:* Export scan → PDF/HTML/JSON/CSV with score, findings, remediation.
- *Requirements:* HTML template → PDF (WeasyPrint or headless Chromium), JSON/CSV serializers.
- *Difficulty:* M. *Dependencies:* F5–F11.
- *Security:* Sanitize all embedded scan data; reports contain sensitive recon — warn on export.

**F13. Network map visualization** — *P2*
- *Description:* Interactive topology/graph of devices.
- *Requirements:* React graph lib (react-flow / d3-force).
- *Difficulty:* L. *Dependencies:* F1.

**F14. Trivy integration** — *P2*
- *Description:* Optional deeper package/misconfig scanning on reachable targets.
- *Difficulty:* M. *Dependencies:* Trivy binary present.

**F15. Scheduled/recurring scans & drift alerts** — *P2*
- *Difficulty:* M. *Dependencies:* job scheduler, F7 diffing.

### Future Features (P3)

- **Cloud posture:** AWS/Azure/GCP config scanning, Cloudflare checks (read-only API keys, out of local-first scope).
- **Multi-user / RBAC + PostgreSQL deployment.**
- **Plugin SDK** for third-party check modules.
- **Agent-based internal scanning** for segmented networks.
- **Compliance mappings** (CIS, PCI-DSS quick checks).
- **AI-assisted remediation summaries** (local LLM optional).

---

## Section 3 — System Architecture

### Component diagram

```
┌──────────────────────────────────────────────────────────────┐
│                        Desktop / Browser                       │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  React SPA (TS + Tailwind)                              │   │
│  │  Dashboard · Devices · Scan · Vulns · Reports          │   │
│  └───────────────┬───────────────────────┬────────────────┘   │
│                  │ REST (JSON)            │ WebSocket/SSE      │
└──────────────────┼───────────────────────┼────────────────────┘
                   │                        │ (live progress)
┌──────────────────▼────────────────────────▼───────────────────┐
│  FastAPI (Uvicorn) — bound to 127.0.0.1 only                   │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐     │
│  │ REST     │  │ Auth/Origin  │  │ WebSocket progress hub│     │
│  │ routers  │  │ guard + gate │  │                       │     │
│  └────┬─────┘  └──────────────┘  └───────────┬───────────┘     │
│       │                                       │                 │
│  ┌────▼───────────────────────────────────────▼───────────┐    │
│  │ Service layer (scan orchestration, scoring, reports)   │    │
│  └────┬───────────────┬──────────────┬─────────────┬──────┘    │
│       │               │              │             │           │
│  ┌────▼─────┐  ┌───────▼──────┐ ┌─────▼──────┐ ┌────▼────────┐  │
│  │ Scan job │  │  Scanning    │ │  Vuln      │ │  Report     │  │
│  │ runner   │  │  engine      │ │  engine    │ │  generator  │  │
│  │(asyncio) │  │ (Section 6)  │ │(Section 7) │ │             │  │
│  └────┬─────┘  └───────┬──────┘ └─────┬──────┘ └────┬────────┘  │
│       │                │              │             │           │
│  ┌────▼────────────────▼──────────────▼─────────────▼───────┐   │
│  │ SQLAlchemy 2.0  →  SQLite (default) / PostgreSQL (opt)   │   │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Privileged scan helper (raw sockets) — least privilege    │  │
│  └──────────────────────────────────────────────────────────┘  │
│  External local tools: nmap · Scapy · sslyze · (Trivy)         │
│  Local data: NVD CVE mirror · OUI vendor DB · OSV cache        │
└────────────────────────────────────────────────────────────────┘
```

### Data flow — end to end

1. **User starts a scan.** SPA `POST /api/scans` with target (CIDR/host) + profile. Backend validates target, enforces the **authorization gate** (user must confirm they own/are authorized to scan the target), creates a `scans` row (`status=queued`) + a `scan_jobs` row, returns `scan_id`. Frontend opens `WS /api/scans/{id}/stream`.
2. **Backend performs discovery.** The asyncio job runner picks up the job, transitions `status=running`, and drives the scanning engine: discovery (F1) → port scan (F2) → service/version (F3) → OS (F4) → web/TLS checks (F9/F10). Each stage emits progress events to the WS hub.
3. **Results are stored.** As each host/port/service resolves, rows are written to `devices`, `ports`, `services`. Everything is tied to `scan_id` so scans are immutable historical snapshots.
4. **Vulnerabilities are identified.** After service detection, the vuln engine matches `(product, version)` against the local CVE mirror + OSV, writes `vulnerabilities` rows (join to `cves`), and generates `recommendations`.
5. **Reports are generated.** On demand (`POST /api/reports`) the report generator composes score + findings + remediation into HTML→PDF/JSON/CSV, stored in `reports`.
6. **Dashboard updates.** Live during the scan via WebSocket; on completion the SPA refetches summary endpoints. Score and top findings render on the dashboard.

### Frontend ↔ backend communication
- **REST/JSON** for all CRUD and control (documented via FastAPI's OpenAPI).
- **WebSocket** (fallback SSE) for scan progress + live findings — one channel per scan.
- **Local-only:** server binds `127.0.0.1`; SPA served same-origin (or Tauri `tauri://` origin allow-listed). No external calls except CVE-feed refresh (user-initiated, cacheable offline).

### Background scanning architecture (MVP, $0-infra)
- A single `ScanJobRunner` started in FastAPI's lifespan runs an asyncio loop that polls the `scan_jobs` table for `queued` work, respecting a max-concurrency cap.
- Each scan runs as an asyncio task; blocking tools (nmap subprocess, Scapy) run in a thread/process pool so the event loop stays responsive.
- State lives in SQLite (`scan_jobs.status`, `progress`, `heartbeat_at`), so a crash/restart can requeue orphaned `running` jobs. **No Redis/Celery** — swap to ARQ+Redis only if multi-worker scale is ever needed (documented as an optional later path).

---

## Section 4 — Database Design

SQLAlchemy 2.0 models, Alembic migrations. Portable across SQLite/Postgres. Timestamps UTC. IDs are UUID (stored as TEXT in SQLite).

**`users`** *(optional — single-user MVP may skip; present for later multi-user)*
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| username | TEXT UNIQUE | |
| password_hash | TEXT | Argon2id |
| role | TEXT | `admin`/`viewer` |
| created_at | TIMESTAMP | |

**`networks`** — a scanned subnet/scope
| id UUID PK · cidr TEXT · label TEXT · gateway_ip TEXT · owner_confirmed BOOL · created_at | Relationships: 1→N `scans`, 1→N `devices` |

**`scans`** — one scan run (immutable snapshot)
| id UUID PK · network_id FK→networks · profile TEXT (`quick`/`full`/`custom`) · status TEXT (`queued/running/completed/failed/cancelled`) · started_at · finished_at · target TEXT · options JSON · score INT · created_at |

**`scan_jobs`** — background worker state (1:1 with active scans)
| id UUID PK · scan_id FK→scans · status TEXT · progress INT(0-100) · current_stage TEXT · heartbeat_at · error TEXT |

**`devices`** — a host found in a scan
| id UUID PK · scan_id FK→scans · network_id FK→networks · ip TEXT · mac TEXT · hostname TEXT · vendor TEXT · os_family TEXT · os_accuracy INT · is_up BOOL · risk_score INT · first_seen · last_seen | Index (scan_id, ip) |

**`ports`** — a port on a device
| id UUID PK · device_id FK→devices · number INT · protocol TEXT (`tcp`/`udp`) · state TEXT (`open/closed/filtered`) · reason TEXT | Index (device_id, number, protocol) |

**`services`** — service behind a port
| id UUID PK · port_id FK→ports · name TEXT · product TEXT · version TEXT · cpe TEXT · banner TEXT (sanitized) · extra JSON |

**`cves`** — CVE catalog (from NVD/OSV mirror; shared, not per-scan)
| id TEXT PK (`CVE-YYYY-NNNN`) · description TEXT · cvss_v3 REAL · cvss_vector TEXT · severity TEXT (`critical/high/medium/low`) · cwe TEXT · published_at · modified_at · references JSON | Indexed by severity |

**`cpe_matches`** — version-range rules linking CVEs to products (matching engine input)
| id UUID PK · cve_id FK→cves · cpe TEXT · version_start TEXT · version_start_incl BOOL · version_end TEXT · version_end_incl BOOL |

**`vulnerabilities`** — a CVE matched to a service in a scan (the finding)
| id UUID PK · scan_id FK→scans · service_id FK→services · cve_id FK→cves · match_confidence REAL · false_positive BOOL · status TEXT (`open/acknowledged/resolved`) · detected_at | Index (scan_id, cve_id) |

**`recommendations`** — remediation items
| id UUID PK · scan_id FK→scans · device_id FK→devices (nullable) · vulnerability_id FK→vulnerabilities (nullable) · category TEXT · severity TEXT · title TEXT · description TEXT · action TEXT · priority INT |

**`reports`** — generated report artifacts
| id UUID PK · scan_id FK→scans · format TEXT (`pdf/html/json/csv`) · file_path TEXT · summary JSON · created_at |

**Relationships summary:** `networks` 1→N `scans` 1→N `devices` 1→N `ports` 1→N `services`; `services` N→N `cves` via `vulnerabilities`; `cves` 1→N `cpe_matches`; `scans` 1→N `recommendations`/`reports`. `scan_jobs` 1:1 `scans`.

---

## Section 5 — API Design

Base path `/api`. JSON everywhere. FastAPI auto-generates OpenAPI at `/docs`. All endpoints local-origin-guarded (Section 12). Auth is **optional/off by default** for single-user local mode; when enabled, a local session token (HttpOnly cookie) or bearer token is required.

**Auth (optional, off by default)**
- `POST /api/auth/login` → `{token}`; `POST /api/auth/logout`. Only mounted if `AUTH_ENABLED=true`.

**Scans**
- `POST /api/scans/start` — *Purpose:* create + queue a scan. *Request:* `{ "target": "192.168.1.0/24", "profile": "full", "options": {...}, "authorized": true }`. *Response:* `201 { "scan_id": "...", "status": "queued" }`. *Security:* validate CIDR/host (reject public ranges unless explicitly confirmed), require `authorized:true` gate, rate-limit scan creation.
- `GET /api/scans/{id}` — scan status + summary (score, counts, stage). `200` or `404`.
- `GET /api/scans` — paginated history. Query: `?limit&offset&status`.
- `POST /api/scans/{id}/cancel` — cooperative cancel. Sets `cancelled`, signals runner.
- `WS /api/scans/{id}/stream` — live progress + findings events. *Security:* validate scan ownership, close on auth fail.

**Devices**
- `GET /api/devices?scan_id=` — devices for a scan. *Response:* array with ip/mac/os/risk_score/port_count.
- `GET /api/devices/{id}` — full device detail incl. ports, services, vulns.

**Vulnerabilities**
- `GET /api/vulnerabilities?scan_id=&severity=&status=` — filterable findings list.
- `PATCH /api/vulnerabilities/{id}` — `{ "false_positive": true }` or `{ "status": "resolved" }`.

**Reports**
- `POST /api/reports` — `{ "scan_id": "...", "format": "pdf" }` → `202 { "report_id" }`.
- `GET /api/reports/{id}` — metadata + download URL.
- `GET /api/reports/{id}/download` — streams file. *Security:* path-traversal-safe file serving from a fixed reports dir.

**System / data**
- `GET /api/health` — liveness.
- `GET /api/cve/status` — local mirror freshness.
- `POST /api/cve/refresh` — pull latest NVD/OSV deltas (user-initiated).

**Cross-cutting security concerns:** input validation via Pydantic; per-endpoint rate limiting; consistent error envelope `{error:{code,message}}`; never reflect unsanitized banners/hostnames in responses without escaping on render; CORS locked to localhost/tauri origins.

---

## Section 6 — Scanning Engine Design

The engine is a pipeline of stages behind a common `Scanner` interface (`async run(target, ctx) -> results`), so stages are individually testable and mockable. nmap is the primary workhorse (wrapped via `python-nmap` or direct subprocess with XML output parsing); Scapy handles raw-packet cases.

### Network discovery
- **ARP scan** (fast, LAN-only): Scapy `ARP(pdst=cidr)/Ether(broadcast)` or `nmap -sn -PR`. Best for local subnet; returns IP+MAC. MAC→vendor via bundled IEEE OUI file (offline).
- **ICMP discovery:** `nmap -sn -PE` echo requests for hosts across routed segments where ARP won't reach.
- **DHCP discovery** (advanced/P2): passive DHCP listen or DHCP-inform to enumerate leases where permitted.
- *Implementation:* prefer ARP on-LAN (faster, no ICMP filtering issues), fall back to ICMP + TCP-ping (`-PS`) for hosts that block ICMP.

### Port scanning
- **TCP SYN (`-sS`)** — default when root available: fast, half-open, stealthier. **TCP connect (`-sT`)** — fallback without privileges. **UDP (`-sU`)** — top-N common ports only by default (UDP is slow); full UDP is opt-in.
- Configurable port sets: `quick` (top 100), `full` (top 1000), `custom`. Rate/timing via nmap `-T3` default, user-tunable, with a hard cap to prevent self-DoS.

### Service detection
- **nmap `-sV`** version probes as primary. **Banner grabbing** as supplement: bounded async socket reads for HTTP/SSH/FTP/SMTP; parse `Server:`, SSH ident, etc. Normalize to `(product, version, cpe)`. Sanitize banners before storage.

### OS detection
- **nmap `-O`** TCP/IP stack fingerprinting (primary), reported with accuracy %. **TTL heuristics** as a cheap fallback (initial TTL ~64→Linux, ~128→Windows, ~255→network gear). Always surfaced as probabilistic guess, never asserted.

**Privilege handling:** SYN/OS/ARP scans need raw sockets → root/`CAP_NET_RAW`. Isolate these in a minimal privileged helper; the main service runs unprivileged and requests scans over a narrow IPC. Gracefully degrade to connect-scan when privileges are unavailable, and tell the user what was skipped.

---

## Section 7 — Vulnerability Engine Design

**Goal:** turn `(product, version)` into a ranked, deduplicated, low-false-positive list of CVEs with remediation.

### CVE database management
- **Local NVD mirror:** download NVD JSON feeds on first run, store parsed rows in `cves` + `cpe_matches`. Refresh via delta feeds (`POST /api/cve/refresh`). Fully offline after initial sync — good for privacy and $0.
- **OSV.dev:** queried (or mirrored) for package-ecosystem vulns; no API key, free.
- **Optional Trivy:** shell out to local Trivy for supplementary findings when installed.

### Matching algorithm
1. Normalize detected service to a **CPE** (`cpe:2.3:a:apache:http_server:2.4.49`) using nmap CPE output + a normalization map.
2. Look up candidate `cpe_matches` by product.
3. **Version comparison** against `version_start*/version_end*` ranges using a proper version comparator (`packaging.version`, with vendor-specific fallbacks for non-PEP440 schemes). Handle inclusive/exclusive bounds.
4. Emit a `vulnerability` row per match with a **`match_confidence`** score derived from CPE specificity + version certainty.

### Severity calculation
- Take CVSS v3 base score from the CVE record → map to `critical (9.0–10)/high (7.0–8.9)/medium (4.0–6.9)/low (0.1–3.9)`. Store both numeric and band. Missing CVSS → derive from CWE heuristics + mark low-confidence.

### False-positive handling
- Confidence threshold below which findings are flagged "needs review" not "confirmed."
- User can mark `false_positive` (persisted, excluded from score).
- Prefer precise version matches; when only product is known (no version), tag as "potential" and down-weight.
- Suppress CVEs where nmap already resolved a patched sub-version.

**Worked example (as required):**
```
Input:   Service = Apache 2.4.49   (cpe:2.3:a:apache:http_server:2.4.49)
Match:   CVE-2021-41773 → cpe range: 2.4.49 ≤ v ≤ 2.4.49  → MATCH
Output:  CVE = CVE-2021-41773
         Severity = Critical (CVSS 9.8)
         Recommendation = Upgrade Apache httpd to 2.4.51 or later (path traversal / RCE).
```

---

## Section 8 — Security Scoring System

**Range:** 0–100 per network and per device (100 = healthy, 0 = critical exposure). Deterministic, explainable, stored with its factor breakdown.

**Model:** start at 100, subtract weighted penalties, floor at 0.

| Factor | Penalty (per occurrence, capped) |
|---|---|
| Critical CVE (unpatched) | −25 (cap −60) |
| High CVE | −12 |
| Medium CVE | −5 |
| Low CVE | −1 |
| Open critical port exposed (e.g., 23/3389/445 externally reachable) | −10 |
| Outdated software (EOL/known-vulnerable version) | −8 |
| Weak/deprecated TLS (SSLv3/TLS1.0, weak ciphers, expired cert) | −8 |
| Unnecessary exposed service (telnet, ftp, unauthenticated db) | −6 |
| Missing security headers (HSTS/CSP/X-Frame-Options) | −2 each (cap −8) |
| Default credentials / anonymous access detected | −20 |

**Aggregation:** device score = 100 − Σ(device penalties). Network score = severity-weighted aggregate of device scores (worst devices dominate) rather than a plain mean, so one critical host can't hide behind many healthy ones: e.g. `network = min(mean(device_scores), 100 − worst_device_penalty_share)`. Map final number to a letter grade (A–F) for the dashboard.

**Explainability:** every score persists the contributing factors (`score`, list of `{factor, weight, evidence}`), rendered in the UI as "why this score" — this is a key differentiator and prevents a black-box number.

---

## Section 9 — Frontend Design

React + TS + Tailwind, Vite. State via TanStack Query (server cache) + lightweight Zustand for UI state. Charts via Recharts; topology via react-flow. Follow the **dataviz skill** for all charts (consistent, theme-aware, accessible palette). Dark/light theme aware.

**Global:** left nav (Dashboard/Devices/Scan/Vulnerabilities/Reports), top bar with current network + "New Scan" CTA, toast notifications, live-scan indicator.

**Dashboard**
- Hero **security score** gauge (0–100 + A–F grade) with "why this score" drill-down.
- Stat tiles: devices found, open ports, critical/high findings, last scan time.
- Recent scans list (score trend sparkline).
- Critical findings feed (top N by severity).
- *Interactions:* click a finding → deep link to its device/vuln.

**Devices**
- **Network map** (react-flow force graph): nodes = devices colored by risk, edges to gateway.
- Sortable/filterable device table (IP, hostname, OS, open ports, risk).
- Device detail drawer: ports, services+versions, per-device vulns, per-device score.

**Scan**
- Scan config: target (CIDR/host with validation + the **authorization checkbox gate**), profile (quick/full/custom), advanced options (port ranges, UDP toggle, timing).
- **Live progress**: stage stepper (discovery→ports→services→OS→vulns), progress bar, streaming found-devices list via WebSocket, cancel button.

**Vulnerabilities**
- CVE table: severity badges, CVE id, affected device/service, CVSS, status.
- Filters: severity, status (open/ack/resolved), false-positive toggle.
- Row expand: description, references, remediation, "mark false positive / resolved."
- *Data viz:* severity distribution bar, findings-over-time trend.

**Reports**
- Scan picker → format selection (PDF/HTML/JSON/CSV) → generate → download.
- Preview pane of the HTML report.
- Export warning (results are sensitive).

**Visualization ideas:** risk-heatmap of devices×ports, TLS-grade badges, score-trend line across scans, CVE severity donut. All must degrade gracefully with empty/partial data (scan in progress).

---

## Section 10 — Development Roadmap

Complexity in relative T-shirt sizes; assumes one focused developer.

**Phase 0 — Project setup** *(complexity S)*
- Deliverables: monorepo scaffold (Section 14), FastAPI hello-world bound to localhost, React+Vite+Tailwind shell, SQLite+SQLAlchemy+Alembic wired, Docker Compose, CI (lint/test), pre-commit hooks.
- Milestone: `docker compose up` serves an empty dashboard talking to `/api/health`.

**Phase 1 — MVP scanner** *(complexity L)*
- Deliverables: discovery (F1), port scan (F2), service detection (F3), basic OS (F4), scan persistence (F7), background job runner, scan REST + WebSocket progress.
- Milestone: start a scan from an API call, watch it run, see devices/ports/services persisted.

**Phase 2 — Dashboard** *(complexity L)*
- Deliverables: Dashboard, Devices (table + map), Scan page with live progress, basic scoring (F5), score UI.
- Milestone: full happy-path scan driven entirely from the UI with a live progress view and a score.

**Phase 3 — Vulnerability engine** *(complexity XL)*
- Deliverables: CVE mirror pipeline (NVD/OSV), CPE normalization + version-range matching (F8), severity, false-positive handling, Vulnerabilities page, web (F9) + TLS (F10) checks, recommendations (F11).
- Milestone: Apache-2.4.49→CVE-2021-41773 example works end-to-end with remediation.

**Phase 4 — Reporting** *(complexity M)*
- Deliverables: report generator (PDF/HTML/JSON/CSV) (F12), Reports page, refined explainable scoring.
- Milestone: one-click professional PDF report for a completed scan.

**Phase 5 — Advanced security features** *(complexity L–XL)*
- Deliverables: network map polish (F13), Trivy integration (F14), scheduled scans + drift alerts (F15), Tauri desktop packaging, optional auth + PostgreSQL path.
- Milestone: recurring scans with change alerts + a shippable desktop app.

---

## Section 11 — Testing Strategy

**Unit tests** (pytest, Vitest)
- Scanner stage functions with **recorded nmap XML fixtures** (parse without live scanning).
- Banner/protocol parsers against captured samples.
- CVE matching: version-range comparator edge cases (pre-release, non-semver, inclusive/exclusive bounds), CPE normalization.
- Scoring engine: deterministic factor→score assertions.
- Frontend: component + hook tests, especially data-rendering and empty/loading states.

**Integration tests**
- Full scan workflow against a **controlled lab** (Docker network of intentionally-vulnerable containers, e.g., a pinned vulnerable Apache image) — never against third-party hosts.
- API contract tests (schema validation against OpenAPI).
- DB migration round-trips (Alembic up/down).

**Security tests**
- Input validation: malformed CIDRs, injection in target/options, path traversal on report download.
- Authorization gate enforcement (scan refused without `authorized:true`).
- Permission handling: graceful degradation when raw sockets unavailable.
- Abuse prevention: rate-limit + self-DoS guard tests; localhost-origin enforcement; XSS via crafted banners rendered in report/UI.

**Performance tests**
- Large network (/16 simulation), thousands of ports, concurrency caps, memory/streaming under load, WebSocket backpressure. Establish baselines and regression thresholds in CI (nightly, not per-PR).

---

## Section 12 — Security Considerations

- **Running privileged scans:** raw-socket capability isolated in a minimal helper (least privilege, `CAP_NET_RAW` not full root where possible); main app runs unprivileged; document the trust boundary. Never run the whole stack as root.
- **Authorization / preventing unauthorized scanning:** hard gate requiring explicit user confirmation of ownership/authorization; default-deny public IP ranges (must be explicitly overridden); log scan authorizations; prominent legal/ethical notice. This is both an ethical and a safety control.
- **Protecting scan results:** results are sensitive recon data. Store the SQLite file with restrictive perms (0600), in a user-scoped app-data dir; optional at-rest encryption (SQLCipher) as a later toggle; never transmit off-device without explicit user action.
- **Secure storage & secrets:** no plaintext creds; if auth enabled, Argon2id password hashing; API tokens HttpOnly + localhost-scoped.
- **Code-execution risks:** never `shell=True`; pass nmap/Trivy args as argv arrays; strictly validate/allow-list all user-supplied scan options before they reach a subprocess. Parse tool output as data, never `eval`. Sanitize all banners/hostnames before storage and escape on render (XSS in dashboard/reports).
- **Dependency vulnerabilities:** pin deps, `pip-audit`/`npm audit` + Dependabot in CI, SBOM generation, minimal dependency surface. Vendor the OUI/CVE data with integrity checks.
- **Network posture of the app itself:** bind `127.0.0.1` only, strict CORS/origin allow-list (localhost + `tauri://`), CSRF protection on state-changing routes, rate limiting.
- **Privacy:** all CVE data cacheable locally so scans need no outbound calls; the only network egress is user-initiated CVE refresh. No telemetry by default.

---

## Section 13 — Open Source Strategy

- **License:** **MIT** (or Apache-2.0 for explicit patent grant). Recommend **Apache-2.0** for a security tool — patent clause protects contributors/users. Add a prominent **responsible-use / legal disclaimer** ("scan only networks you own or are authorized to test").
- **Repository structure:** monorepo (Section 14) with clear `frontend/`, `backend/` separation.
- **Documentation:** `README` (quickstart, screenshots), `docs/` (architecture, this plan, scanning ethics, API reference from OpenAPI, contributing), `SECURITY.md` (responsible disclosure), `CODE_OF_CONDUCT.md`.
- **Contribution guidelines:** `CONTRIBUTING.md` with dev setup, coding standards, PR checklist, DCO/sign-off; "good first issue" labels.
- **Issue/PR templates:** `.github/ISSUE_TEMPLATE/` (bug, feature, scanner-module proposal, security→private), `PULL_REQUEST_TEMPLATE.md`.
- **CI/CD (GitHub Actions):** lint (ruff/eslint) + type-check (mypy/tsc) + unit tests on every PR; integration tests + `pip-audit`/`npm audit` + CodeQL nightly; build Docker image + Tauri bundles on tagged release; auto-publish OpenAPI docs.

---

## Section 14 — Recommended Folder Structure

```
sentinelscan/
├── frontend/                 # React + TS + Tailwind SPA (Vite)
│   ├── src/
│   │   ├── pages/            # Dashboard, Devices, Scan, Vulnerabilities, Reports
│   │   ├── components/       # shared UI (charts, tables, gauges, map)
│   │   ├── api/              # typed REST/WS client (generated from OpenAPI)
│   │   ├── hooks/  stores/  lib/
│   │   └── main.tsx
│   └── package.json
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── main.py           # app factory, lifespan, localhost bind
│   │   ├── api/routers/      # scans, devices, vulnerabilities, reports, system
│   │   ├── core/             # config, security/origin-guard, auth
│   │   ├── db/               # SQLAlchemy models, session, Alembic migrations
│   │   ├── services/         # orchestration, scoring, reports
│   │   └── workers/          # asyncio scan job runner
│   ├── pyproject.toml
│   └── tests/
├── scanner/                  # scanning engine (importable, standalone-testable)
│   ├── discovery/            # ARP, ICMP, DHCP
│   ├── ports/                # TCP/UDP scan wrappers
│   ├── services/             # nmap -sV wrapper, banner grabbers, parsers
│   ├── os_detection/
│   ├── web/  tls/            # header checks, sslyze wrapper
│   └── privileged_helper/    # least-privilege raw-socket helper
├── vuln_engine/              # CVE data pipeline + matching
│   ├── feeds/                # NVD/OSV sync
│   ├── matching/             # CPE normalization, version comparator
│   └── data/                 # local CVE mirror + OUI vendor DB
├── reports/                  # report templates + generators (PDF/HTML/JSON/CSV)
├── database/                 # seed data, schema docs
├── docker/                   # Dockerfiles, docker-compose.yml
├── docs/                     # DEVELOPMENT_PLAN.md, architecture, ethics, API
├── scripts/                  # dev/setup/data-sync utilities
├── .github/                  # CI workflows, issue/PR templates
├── LICENSE  README.md  SECURITY.md  CONTRIBUTING.md
```

**Directory purposes:** `frontend/` (dashboard SPA), `backend/` (API + orchestration + persistence), `scanner/` (pure scanning logic, decoupled so it's unit-testable and reusable as a library/CLI), `vuln_engine/` (CVE data + matching, isolated because it's the most complex subsystem), `reports/` (presentation of findings), `database/` (schema/seed assets), `docker/` (reproducible run), `docs/` (all docs incl. this plan), `.github/` (OSS automation).

---

## Section 15 — Final Recommendation

**Recommended MVP scope (Phases 0–2):** device discovery + TCP/UDP port scanning + service/version detection + basic OS fingerprint + persistence + a polished dashboard with live scan progress and a basic explainable security score. This alone is a genuinely useful, demoable product. Ship this before touching the vuln engine.

**Biggest technical challenges (in order):**
1. **Vulnerability matching accuracy** (Phase 3) — CPE normalization + version-range comparison is where false positives are born; it's the hardest and most reputation-critical subsystem.
2. **Privilege management** — raw-socket scanning without running the whole app as root; graceful degradation.
3. **Live progress at scale** — streaming results for large networks without blocking the event loop or overwhelming the UI.
4. **CVE data freshness offline** — keeping a local mirror current while preserving the $0/privacy goals.

**Highest portfolio value:** the **explainable security score + polished dashboard with live scanning** (unique, visual, demoable) and the **CVE-matching engine** (demonstrates real security depth via the Apache→CVE-2021-41773 flow). These two are what make it stand out from "yet another nmap wrapper."

**What to avoid initially:** multi-user/RBAC + PostgreSQL, cloud posture scanning, Tauri packaging, scheduled scans, plugin SDK, active/intrusive web fuzzing, and any exploitation features. All of these are Phase 5+ or explicitly out of scope. Do not build enterprise features before the core scan-to-score-to-report loop is solid and pleasant to use.
