"""Host discovery without raw sockets.

Raw ARP/ICMP need root. To stay privilege-free we treat a host as "up" if it
accepts a TCP connection on any of a handful of common ports (a TCP ping), and
resolve its hostname via reverse DNS. When run as root with Scapy available an
ARP backend can be added behind the same ``discover_hosts`` interface.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from scanner.models import DiscoveredHost


def expand_target(target: str) -> list[str]:
    """Expand a CIDR, single IP, or hostname into a list of host IPs.

    Raises ValueError on obviously invalid input so the API layer can reject it.
    """
    target = target.strip()
    if not target:
        raise ValueError("empty target")

    # CIDR range
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 65536:
            raise ValueError("target range too large (>/16); refine the scope")
        hosts = [str(h) for h in net.hosts()]
        # /32 and /31 have no "hosts"; fall back to the network address.
        return hosts or [str(net.network_address)]

    # Single IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # Hostname → resolve
    try:
        return [socket.gethostbyname(target)]
    except socket.gaierror as exc:  # pragma: no cover - network dependent
        raise ValueError(f"cannot resolve host: {target}") from exc


async def _tcp_ping(ip: str, ports: list[int], timeout: float) -> bool:
    """Return True if any of ``ports`` accepts (or actively refuses) a connection.

    A connection refused (RST) still proves the host is alive, so we treat it
    as "up" too — only timeouts/unreachable count as down.
    """
    for port in ports:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except asyncio.TimeoutError:
            continue
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


async def _reverse_dns(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


async def discover_hosts(
    ips: list[str],
    discovery_ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 128,
    assume_up_single: bool = True,
) -> list[DiscoveredHost]:
    """Probe ``ips`` and return the ones that appear to be up.

    ``assume_up_single`` treats an explicit single-host target as up even if the
    TCP ping fails, so users can still scan a host that filters the probe ports.
    """
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str) -> DiscoveredHost | None:
        async with sem:
            up = await _tcp_ping(ip, discovery_ports, timeout)
        if not up and not (assume_up_single and len(ips) == 1):
            return None
        hostname = await _reverse_dns(ip)
        return DiscoveredHost(ip=ip, hostname=hostname, is_up=True)

    results = await asyncio.gather(*(probe(ip) for ip in ips))
    return [h for h in results if h is not None]
