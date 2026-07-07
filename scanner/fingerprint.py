"""Service and version detection via banner grabbing.

For each open port we do a light, protocol-aware probe:
  * HTTP(S) ports: send a HEAD/GET and read the ``Server`` header.
  * SSH/FTP/SMTP/POP/IMAP: read the greeting banner the server sends first.
  * Everything else: read whatever bytes arrive within the timeout.

Banners are sanitized (control chars stripped, length-capped) before storage to
avoid log/HTML injection. Product+version are extracted with a small regex table
and normalized to a CPE where possible so the vuln engine can match them.
"""

from __future__ import annotations

import asyncio
import re

from scanner.common_ports import WELL_KNOWN
from scanner.models import PortResult, ServiceInfo

_MAX_BANNER = 512

# HTTP-ish ports where we should speak HTTP to elicit a Server header.
_HTTP_PORTS = {80, 81, 591, 2480, 3000, 5000, 8000, 8008, 8080, 8081, 8443,
               8888, 9000, 9200, 9090, 443, 8443}
# Ports where the server greets first — just read.
_BANNER_FIRST = {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379}
_BANNER_FIRST_NAMES = {"ssh", "ftp", "telnet", "smtp", "pop3", "imap", "submission"}

# (regex, product, service-name, cpe-vendor:product) applied to a banner.
_SIGNATURES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"Apache/(\d[\d.]*)", re.I), "Apache httpd", "http", "apache:http_server"),
    (re.compile(r"nginx/(\d[\d.]*)", re.I), "nginx", "http", "nginx:nginx"),
    (re.compile(r"OpenSSH[_/ ]?(\d[\w.]*)", re.I), "OpenSSH", "ssh", "openbsd:openssh"),
    (re.compile(r"lighttpd/(\d[\d.]*)", re.I), "lighttpd", "http", "lighttpd:lighttpd"),
    (re.compile(r"Microsoft-IIS/(\d[\d.]*)", re.I), "Microsoft IIS", "http", "microsoft:iis"),
    (re.compile(r"vsftpd (\d[\d.]*)", re.I), "vsftpd", "ftp", "vsftpd:vsftpd"),
    (re.compile(r"ProFTPD (\d[\d.]*)", re.I), "ProFTPD", "ftp", "proftpd:proftpd"),
    (re.compile(r"Exim (\d[\d.]*)", re.I), "Exim", "smtp", "exim:exim"),
    (re.compile(r"Postfix", re.I), "Postfix", "smtp", "postfix:postfix"),
    (re.compile(r"MySQL[^\d]*(\d[\d.]*)", re.I), "MySQL", "mysql", "oracle:mysql"),
    (re.compile(r"Redis", re.I), "Redis", "redis", "redis:redis"),
]


def _sanitize(raw: bytes) -> str | None:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    # Strip control chars except newline/tab, collapse whitespace, cap length.
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch >= " ")
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text[:_MAX_BANNER] or None


def _server_header(raw_http: str) -> str | None:
    for line in raw_http.split("\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def _identify(banner: str, service_name: str) -> ServiceInfo:
    info = ServiceInfo(name=service_name, banner=banner)
    for pattern, product, svc, cpe_pp in _SIGNATURES:
        m = pattern.search(banner)
        if m:
            info.product = product
            info.name = svc
            version = m.group(1) if m.groups() else None
            info.version = version
            if version:
                info.cpe = f"cpe:2.3:a:{cpe_pp}:{version}"
            else:
                info.cpe = f"cpe:2.3:a:{cpe_pp}:*"
            break
    return info


async def _http_probe(ip: str, reader, writer, timeout: float) -> str | None:
    """Send an HTTP HEAD request and return the Server header (or raw response)."""
    request = (
        f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
        "User-Agent: SentinelScan\r\nConnection: close\r\n\r\n"
    )
    writer.write(request.encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    return _server_header(text) or _sanitize(raw)


async def _grab(ip: str, port: int, timeout: float) -> tuple[str | None, str]:
    """Return (banner, base_service_name) for an open port.

    Strategy: banner-first protocols are read passively. HTTP-ish and unknown
    ports get an active HTTP probe; unknown ports first wait briefly for a
    self-announcing banner, then fall back to the HTTP probe if the server is
    silent (HTTP servers do not speak until spoken to).
    """
    base_name = WELL_KNOWN.get(port, "unknown")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return None, base_name

    try:
        if port in _BANNER_FIRST or base_name in _BANNER_FIRST_NAMES:
            raw = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return _sanitize(raw), base_name

        if port in _HTTP_PORTS or base_name in ("http", "https"):
            banner = await _http_probe(ip, reader, writer, timeout)
            return banner, "http"

        # Unknown port: brief passive read, then HTTP fallback if silent.
        try:
            raw = await asyncio.wait_for(reader.read(1024), timeout=min(timeout, 1.0))
        except asyncio.TimeoutError:
            raw = b""
        if raw:
            return _sanitize(raw), base_name
        try:
            banner = await _http_probe(ip, reader, writer, timeout)
        except (asyncio.TimeoutError, OSError):
            banner = None
        return (banner, "http" if banner else base_name)
    except (asyncio.TimeoutError, OSError):
        return None, base_name
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def fingerprint_ports(
    ip: str,
    ports: list[PortResult],
    timeout: float = 2.0,
    concurrency: int = 50,
) -> None:
    """Attach a ServiceInfo to each open port (mutates in place)."""
    sem = asyncio.Semaphore(concurrency)

    async def one(pr: PortResult) -> None:
        async with sem:
            banner, base_name = await _grab(ip, pr.number, timeout)
        if banner:
            pr.service = _identify(banner, base_name)
        else:
            pr.service = ServiceInfo(name=base_name)

    await asyncio.gather(*(one(pr) for pr in ports))
