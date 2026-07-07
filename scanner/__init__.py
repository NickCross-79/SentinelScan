"""SentinelScan scanning engine.

A pure-Python, privilege-free scanning engine. It uses asyncio TCP connect
scans and banner grabbing so it runs without root or nmap, while remaining
easy to extend with an nmap backend later (see ``PROFILES`` / ``PortScanner``).
"""

from scanner.engine import ScanEngine, ScanProgress
from scanner.models import (
    DiscoveredHost,
    PortResult,
    ScanResult,
    ServiceInfo,
)
from scanner.profiles import PROFILES, ScanProfile

__all__ = [
    "ScanEngine",
    "ScanProgress",
    "ScanResult",
    "DiscoveredHost",
    "PortResult",
    "ServiceInfo",
    "PROFILES",
    "ScanProfile",
]
