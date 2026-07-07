"""Scan profiles: named bundles of scan options."""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.common_ports import TOP_100_TCP, TOP_1000_TCP


@dataclass
class ScanProfile:
    name: str
    ports: list[int]
    connect_timeout: float = 1.0      # per-port TCP connect timeout (seconds)
    max_concurrency: int = 200        # simultaneous connect attempts
    banner_timeout: float = 2.0       # read timeout for banner grabbing
    grab_banners: bool = True
    discovery_ports: list[int] = field(
        default_factory=lambda: [80, 443, 22, 445, 3389, 8080]
    )


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", ports=TOP_100_TCP, max_concurrency=256),
    "full": ScanProfile(name="full", ports=TOP_1000_TCP, max_concurrency=400),
}


def build_profile(name: str, custom_ports: list[int] | None = None) -> ScanProfile:
    """Return a profile by name, or a custom profile from an explicit port list."""
    if name == "custom" and custom_ports:
        return ScanProfile(name="custom", ports=sorted(set(custom_ports)))
    if name in PROFILES:
        return PROFILES[name]
    return PROFILES["quick"]
