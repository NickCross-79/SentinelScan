"""Curated port lists and a well-known service map.

Kept as plain data so it can be swapped for nmap-services later without
touching the engine.
"""

from __future__ import annotations

# Top ~100 commonly interesting TCP ports (nmap top-ports flavoured).
TOP_100_TCP: list[int] = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
    3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5060, 5101, 5190, 5357,
    5432, 5555, 5601, 5631, 5666, 5800, 5900, 5985, 6000, 6001, 6379, 6646,
    7070, 7777, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100,
    9200, 9300, 10000, 11211, 27017, 32768, 49152, 49153, 49154, 49157,
]

# Top ~1000 approximation for the "full" profile: well-known range + extras.
TOP_1000_TCP: list[int] = sorted(
    set(TOP_100_TCP)
    | set(range(1, 1025))
    | {
        1433, 1521, 1723, 2049, 2082, 2083, 2181, 3000, 3306, 3389, 4444, 4567,
        5432, 5601, 5672, 5900, 5984, 6379, 7000, 7001, 7077, 8000, 8008, 8080,
        8081, 8086, 8088, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999,
        11211, 15672, 27017, 27018, 28017, 50000, 50070,
    }
)

# Ports that are dangerous when reachable — feed the scoring engine.
CRITICAL_PORTS: dict[int, str] = {
    21: "FTP (often cleartext / anonymous)",
    23: "Telnet (cleartext credentials)",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    11211: "Memcached (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
}

# Minimal well-known-name lookup used when no banner reveals the service.
WELL_KNOWN: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 3000: "http", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5985: "wsman",
    6379: "redis", 8000: "http", 8080: "http-proxy", 8443: "https-alt",
    8888: "http", 9200: "http", 11211: "memcached", 27017: "mongodb",
}
