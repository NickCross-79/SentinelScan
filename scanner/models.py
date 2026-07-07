"""Plain result objects produced by the scanning engine.

These are deliberately framework-free dataclasses so the engine can be used as
a standalone library or CLI, independent of the FastAPI/DB layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    """Service identified behind an open port."""

    name: str = "unknown"
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class PortResult:
    number: int
    protocol: str = "tcp"
    state: str = "open"  # open | closed | filtered
    reason: str = "syn-ack"
    service: ServiceInfo | None = None


@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_family: str | None = None
    os_accuracy: int | None = None
    is_up: bool = True
    ports: list[PortResult] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    hosts: list[DiscoveredHost] = field(default_factory=list)

    @property
    def up_hosts(self) -> list[DiscoveredHost]:
        return [h for h in self.hosts if h.is_up]
