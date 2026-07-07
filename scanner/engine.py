"""Top-level scan orchestration.

``ScanEngine.run`` drives the pipeline (discovery → port scan → fingerprint) and
emits ``ScanProgress`` events through an async callback so the API layer can
stream them over WebSocket. The engine has no DB or web dependencies.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from scanner.discovery import discover_hosts, expand_target
from scanner.fingerprint import fingerprint_ports
from scanner.models import ScanResult
from scanner.ports import scan_ports
from scanner.profiles import ScanProfile, build_profile

STAGES = ("discovery", "ports", "services", "done")


@dataclass
class ScanProgress:
    stage: str
    percent: int
    message: str
    host: str | None = None


ProgressHandler = Callable[[ScanProgress], Awaitable[None]] | None


class ScanEngine:
    def __init__(self, profile: ScanProfile):
        self.profile = profile

    @classmethod
    def from_profile_name(
        cls, name: str, custom_ports: list[int] | None = None
    ) -> "ScanEngine":
        return cls(build_profile(name, custom_ports))

    async def run(
        self, target: str, on_progress: ProgressHandler = None
    ) -> ScanResult:
        async def emit(stage: str, percent: int, message: str, host: str | None = None):
            if on_progress:
                await on_progress(ScanProgress(stage, percent, message, host))

        result = ScanResult(target=target)

        # 1. Discovery
        await emit("discovery", 2, f"Expanding target {target}")
        ips = expand_target(target)
        await emit("discovery", 5, f"Probing {len(ips)} address(es) for live hosts")
        hosts = await discover_hosts(
            ips,
            self.profile.discovery_ports,
            timeout=self.profile.connect_timeout,
        )
        result.hosts = hosts
        await emit("discovery", 20, f"Found {len(hosts)} live host(s)")

        if not hosts:
            await emit("done", 100, "No live hosts found")
            return result

        # 2. Port scan + 3. fingerprint, per host, sharing the 20→100 band.
        span = 80 / len(hosts)
        for idx, host in enumerate(hosts):
            base = 20 + span * idx

            async def port_progress(done: int, total: int, _base=base, _host=host):
                pct = int(_base + (span * 0.7) * (done / max(total, 1)))
                await emit("ports", pct, f"Scanning ports on {_host.ip}", _host.ip)

            host.ports = await scan_ports(
                host.ip,
                self.profile.ports,
                timeout=self.profile.connect_timeout,
                concurrency=self.profile.max_concurrency,
                progress_cb=port_progress,
            )
            await emit(
                "ports",
                int(base + span * 0.7),
                f"{host.ip}: {len(host.ports)} open port(s)",
                host.ip,
            )

            if self.profile.grab_banners and host.ports:
                await emit("services", int(base + span * 0.75),
                           f"Identifying services on {host.ip}", host.ip)
                await fingerprint_ports(
                    host.ip, host.ports, timeout=self.profile.banner_timeout
                )
            host.os_family, host.os_accuracy = _guess_os(host)

        await emit("done", 100, "Scan complete")
        return result


def _guess_os(host) -> tuple[str | None, int | None]:
    """Very rough OS hint from open-port composition (placeholder for TTL/nmap -O)."""
    open_nums = {p.number for p in host.ports}
    if {135, 139, 445} & open_nums or 3389 in open_nums:
        return "Windows", 60
    if {22} & open_nums:
        return "Linux/Unix", 55
    return None, None
