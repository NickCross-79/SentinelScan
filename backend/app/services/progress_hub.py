"""In-process pub/sub for live scan progress.

Each scan gets a set of asyncio.Queues (one per connected WebSocket). The
orchestrator publishes events; WebSocket handlers subscribe and drain. No
external broker — this is the $0-infra live-progress channel.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict


class ProgressHub:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._last: dict[str, dict] = {}

    async def publish(self, scan_id: str, event: dict) -> None:
        self._last[scan_id] = event
        for q in list(self._subscribers.get(scan_id, ())):
            await q.put(event)

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers[scan_id].add(q)
        # Replay the most recent event so a late subscriber sees current state.
        if scan_id in self._last:
            q.put_nowait(self._last[scan_id])
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        subs = self._subscribers.get(scan_id)
        if subs and q in subs:
            subs.discard(q)
            if not subs:
                self._subscribers.pop(scan_id, None)

    def clear(self, scan_id: str) -> None:
        self._last.pop(scan_id, None)
        self._subscribers.pop(scan_id, None)


hub = ProgressHub()
