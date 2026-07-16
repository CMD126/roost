"""Reads the OS's ARP/neighbor table to resolve an IP's MAC address.

Relies on the table already being populated — call this right after a
successful ping to the same IP, while the kernel's ARP cache is still fresh.
"""

from __future__ import annotations

import asyncio
import platform
import re

_IS_WINDOWS = platform.system() == "Windows"
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


async def _run(*args: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2)
    except (asyncio.TimeoutError, OSError):
        return ""
    return stdout.decode(errors="ignore")


async def get_mac(ip: str) -> str | None:
    if _IS_WINDOWS:
        output = await _run("arp", "-a", ip)
    else:
        output = await _run("ip", "neigh", "show", ip)
        if not output:
            output = await _run("arp", "-n", ip)

    match = _MAC_RE.search(output)
    if not match:
        return None
    return match.group(0).replace("-", ":").lower()
