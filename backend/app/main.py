"""FastAPI application factory and lifespan wiring."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.routers import devices, reports, scans, system, vulnerabilities
from backend.app.config import settings
from backend.app.db.base import SessionLocal, init_db
from backend.app.services.cve_sync import sync_catalog
from backend.app.workers.runner import runner

# Built SPA (frontend/dist) — served at "/" when present so the whole app runs
# as a single local service. Repo root is three levels up from this file.
_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("sentinelscan")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        n = sync_catalog(db)
        log.info("CVE catalog synced: %d record(s)", n)
    finally:
        db.close()
    runner.start()
    log.info("SentinelScan API ready on http://%s:%d", settings.host, settings.port)
    try:
        yield
    finally:
        await runner.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelScan API",
        version="0.1.0",
        description="Local-first network security scanner.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(system.router)
    app.include_router(scans.router)
    app.include_router(devices.router)
    app.include_router(vulnerabilities.router)
    app.include_router(reports.router)

    # Serve the built SPA if present. Hashed assets are served statically; every
    # other non-API GET falls back to index.html for client-side routing.
    if _FRONTEND_DIST.is_dir():
        assets = _FRONTEND_DIST / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        index_html = _FRONTEND_DIST / "index.html"

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str) -> FileResponse:
            candidate = _FRONTEND_DIST / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(index_html)

        log.info("serving SPA from %s", _FRONTEND_DIST)
    return app


app = create_app()
