"""Background scan job runner.

A single asyncio loop started in the app lifespan. It polls the `scan_jobs`
table for queued work and runs scans up to a concurrency cap. State lives in
SQLite, so on restart any orphaned `running` jobs are re-queued. No Redis/Celery
— this is the $0-infra background architecture from the development plan.
"""

from __future__ import annotations

import asyncio
import logging

from backend.app.config import settings
from backend.app.db.base import SessionLocal
from backend.app.db.models import ScanJob
from backend.app.services.orchestrator import run_scan

log = logging.getLogger("sentinelscan.runner")


class ScanJobRunner:
    def __init__(self, poll_interval: float = 0.5, max_concurrency: int | None = None):
        self.poll_interval = poll_interval
        self.max_concurrency = max_concurrency or settings.max_concurrent_scans
        self._task: asyncio.Task | None = None
        self._running: set[asyncio.Task] = set()
        self._stop = asyncio.Event()

    def start(self) -> None:
        self._requeue_orphans()
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="scan-job-runner")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)
        for t in list(self._running):
            t.cancel()
        await asyncio.gather(*self._running, return_exceptions=True)

    def _requeue_orphans(self) -> None:
        db = SessionLocal()
        try:
            orphans = db.query(ScanJob).filter(ScanJob.status == "running").all()
            for job in orphans:
                job.status = "queued"
                job.progress = 0
            if orphans:
                db.commit()
                log.info("re-queued %d orphaned job(s)", len(orphans))
        finally:
            db.close()

    def _claim_next(self) -> str | None:
        """Atomically claim one queued job; return its scan_id."""
        db = SessionLocal()
        try:
            job = (
                db.query(ScanJob)
                .filter(ScanJob.status == "queued")
                .order_by(ScanJob.id)
                .first()
            )
            if job is None:
                return None
            job.status = "claimed"
            db.commit()
            return job.scan_id
        finally:
            db.close()

    async def _run_one(self, scan_id: str) -> None:
        try:
            await run_scan(scan_id)
        finally:
            self._running.discard(asyncio.current_task())

    async def _loop(self) -> None:
        log.info("scan job runner started (max_concurrency=%d)", self.max_concurrency)
        while not self._stop.is_set():
            if len(self._running) < self.max_concurrency:
                scan_id = self._claim_next()
                if scan_id:
                    task = asyncio.create_task(self._run_one(scan_id))
                    self._running.add(task)
                    continue
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                pass


runner = ScanJobRunner()
