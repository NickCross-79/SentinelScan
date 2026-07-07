"""Async TCP connect port scanner.

Uses a bounded pool of asyncio connections. No raw sockets, so no root needed.
The state model mirrors nmap's: ``open`` (accepted), ``closed`` (refused),
``filtered`` (timed out / unreachable).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from scanner.models import PortResult

ProgressCb = Callable[[int, int], Awaitable[None]] | None


async def _probe_port(ip: str, port: int, timeout: float) -> PortResult | None:
    """Return a PortResult for an open port, else None (we only store open ports)."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(number=port, protocol="tcp", state="open", reason="syn-ack")
    except asyncio.TimeoutError:
        return None  # filtered — not stored, keeps result sets small
    except ConnectionRefusedError:
        return None  # closed
    except OSError:
        return None


async def scan_ports(
    ip: str,
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 200,
    progress_cb: ProgressCb = None,
) -> list[PortResult]:
    """Scan ``ports`` on ``ip`` and return the open ones.

    ``progress_cb(done, total)`` is awaited periodically for live updates.
    """
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[PortResult] = []
    total = len(ports)
    done = 0
    lock = asyncio.Lock()

    async def worker(port: int) -> None:
        nonlocal done
        async with sem:
            result = await _probe_port(ip, port, timeout)
        async with lock:
            done += 1
            if result is not None:
                open_ports.append(result)
            if progress_cb and (done % 25 == 0 or done == total):
                await progress_cb(done, total)

    await asyncio.gather(*(worker(p) for p in ports))
    open_ports.sort(key=lambda p: p.number)
    return open_ports
