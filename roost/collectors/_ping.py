"""Cross-platform single-host ping via the system binary (no raw sockets, no admin rights)."""

from __future__ import annotations

import asyncio
import platform
import time

_IS_WINDOWS = platform.system() == "Windows"


async def ping(address: str, timeout: float) -> float | None:
    """Returns round-trip latency in ms, or None if the host didn't reply."""
    if _IS_WINDOWS:
        timeout_ms = max(int(timeout * 1000), 1)
        args = ["ping", "-n", "1", "-w", str(timeout_ms), address]
    else:
        args = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), address]

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return_code = await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
    except (asyncio.TimeoutError, OSError):
        return None

    if return_code != 0:
        return None
    return (time.monotonic() - start) * 1000
