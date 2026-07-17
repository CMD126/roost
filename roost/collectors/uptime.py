"""Checks a configured list of services via HTTP, raw TCP connect, or ping."""

from __future__ import annotations

import asyncio
import time

import httpx

from ..config import UptimeConfig, UptimeTarget
from ..models import UptimeResult
from ._ping import ping


async def _check_http(target: UptimeTarget, timeout: float) -> UptimeResult:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(target.url)
        latency_ms = (time.monotonic() - start) * 1000
        up = 200 <= response.status_code < 400
        return UptimeResult(
            name=target.name,
            address=target.url,
            up=up,
            latency_ms=latency_ms,
            detail=f"HTTP {response.status_code}",
        )
    except Exception as exc:
        # Deliberately broader than httpx.HTTPError: a malformed url in a
        # target's config (e.g. a typo'd port) raises httpx.InvalidURL,
        # which subclasses Exception directly, not HTTPError — a config
        # typo on one target should mark that target down, not crash the
        # whole app via the asyncio.gather() in collect() below.
        return UptimeResult(
            name=target.name,
            address=target.url,
            up=False,
            latency_ms=None,
            detail=type(exc).__name__,
        )


async def _check_tcp(target: UptimeTarget, timeout: float) -> UptimeResult:
    address = f"{target.address}:{target.port}"
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.address, target.port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return UptimeResult(
            name=target.name,
            address=address,
            up=True,
            latency_ms=(time.monotonic() - start) * 1000,
            detail="open",
        )
    except (TimeoutError, OSError):
        return UptimeResult(
            name=target.name, address=address, up=False, latency_ms=None, detail="closed"
        )


async def _check_ping(target: UptimeTarget, timeout: float) -> UptimeResult:
    latency_ms = await ping(target.address, timeout)
    return UptimeResult(
        name=target.name,
        address=target.address,
        up=latency_ms is not None,
        latency_ms=latency_ms,
        detail="reply" if latency_ms is not None else "no reply",
    )


_CHECKS = {"http": _check_http, "tcp": _check_tcp, "ping": _check_ping}


async def collect(config: UptimeConfig) -> list[UptimeResult]:
    if not config.enabled or not config.targets:
        return []

    async def run_one(target: UptimeTarget) -> UptimeResult:
        check = _CHECKS.get(target.type)
        if check is None:
            return UptimeResult(
                name=target.name,
                address=target.address or target.url,
                up=False,
                latency_ms=None,
                detail=f"unknown type '{target.type}'",
            )
        return await check(target, config.timeout)

    return list(await asyncio.gather(*(run_one(t) for t in config.targets)))
