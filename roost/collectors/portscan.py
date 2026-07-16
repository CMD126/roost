"""TCP connect scan + lightweight banner grab against known-live hosts.

Not a substitute for a real scanner (nmap, masscan): fixed port list, single
connect attempt, best-effort banner read. It's meant to surface obviously
exposed services on your own LAN, not to fingerprint exact versions.
"""

from __future__ import annotations

import asyncio

from ..config import PortScanConfig
from ..models import OpenPort, PortScanResult

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5000: "http-alt", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 27017: "mongodb", 32400: "plex",
    2222: "ssh-alt",
}

# Historically common vectors for unauthenticated access or known exploits
# when reachable at all — not a CVE match, just "this deserves a second look".
RISKY_PORTS = {21, 23, 111, 135, 139, 445, 1723, 3389, 5900, 6379, 9200, 27017}

_HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090}


async def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (TimeoutError, OSError):
        return None

    banner = None
    try:
        if port in _HTTP_PORTS:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            await writer.drain()

        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        text = data.decode(errors="ignore").strip()

        if port in _HTTP_PORTS:
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    banner = line.split(":", 1)[1].strip()
                    break
            if banner is None and text:
                banner = text.splitlines()[0][:80]
        elif text:
            banner = text.splitlines()[0][:80]
    except (TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    return banner


async def _scan_port(ip: str, port: int, timeout: float) -> OpenPort | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    except (TimeoutError, OSError):
        return None

    banner = await _grab_banner(ip, port, timeout)
    return OpenPort(
        port=port,
        service=SERVICE_NAMES.get(port, "unknown"),
        banner=banner,
        risky=port in RISKY_PORTS,
    )


async def scan_hosts(ips: list[str], config: PortScanConfig) -> dict[str, PortScanResult]:
    """Scans every (ip, port) pair under a single shared concurrency limit,
    so the total number of in-flight connections stays bounded regardless of
    how many hosts are on the LAN.
    """
    if not config.enabled or not ips:
        return {}

    semaphore = asyncio.Semaphore(max(config.concurrency, 1))

    async def bounded(ip: str, port: int) -> tuple[str, OpenPort | None]:
        async with semaphore:
            return ip, await _scan_port(ip, port, config.timeout)

    pairs = [(ip, port) for ip in ips for port in config.ports]
    results = await asyncio.gather(*(bounded(ip, port) for ip, port in pairs))

    open_ports_by_ip: dict[str, list[OpenPort]] = {ip: [] for ip in ips}
    for ip, open_port in results:
        if open_port is not None:
            open_ports_by_ip[ip].append(open_port)

    return {
        ip: PortScanResult(ip=ip, open_ports=sorted(ports, key=lambda p: p.port))
        for ip, ports in open_ports_by_ip.items()
    }
