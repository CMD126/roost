"""Sweeps a configured CIDR range and reports which hosts answer to ping,
enriched with MAC address and vendor (from the OS ARP table + an offline
OUI database) — reverse DNS alone misses most consumer/IoT devices.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from mac_vendor_lookup import AsyncMacLookup, VendorNotFoundError

from ..config import NetworkConfig
from ..models import NetworkDevice
from ._arp import get_mac
from ._ping import ping

_mac_lookup = AsyncMacLookup()


async def _reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=1.0
        )
        return host
    except (OSError, asyncio.TimeoutError):
        return None


async def _vendor_for(mac: str | None) -> str | None:
    if mac is None:
        return None
    try:
        return await _mac_lookup.lookup(mac)
    except VendorNotFoundError:
        return None


async def collect(config: NetworkConfig) -> list[NetworkDevice]:
    if not config.enabled or not config.cidr:
        return []

    try:
        network = ipaddress.ip_network(config.cidr, strict=False)
    except ValueError:
        return []

    semaphore = asyncio.Semaphore(max(config.concurrency, 1))

    async def probe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> NetworkDevice | None:
        async with semaphore:
            latency_ms = await ping(str(ip), config.timeout)
        if latency_ms is None:
            return None
        hostname, mac = await asyncio.gather(_reverse_dns(str(ip)), get_mac(str(ip)))
        vendor = await _vendor_for(mac)
        return NetworkDevice(
            ip=str(ip), hostname=hostname, latency_ms=latency_ms, mac=mac, vendor=vendor
        )

    results = await asyncio.gather(*(probe(ip) for ip in network.hosts()))
    devices = [d for d in results if d is not None]
    devices.sort(key=lambda d: tuple(int(part) for part in d.ip.split(".")))
    return devices
