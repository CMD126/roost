"""Reads recent alerts from an OpenCanary honeypot's JSON-lines log over SSH.

OpenCanary logs one JSON object per line, both for real interactions with a
decoy service (login attempts, HTTP requests, ...) and for its own internal
startup/housekeeping messages. The two are told apart structurally: a real
interaction always has a non-empty `src_host` (something actually connected
from somewhere); housekeeping lines have `src_host: ""`. That's more robust
than hardcoding OpenCanary's internal logtype numbers.
"""

from __future__ import annotations

import asyncio
import json

from ..config import CanaryConfig
from ..models import SecurityEvent
from .portscan import SERVICE_NAMES


def _classify(logdata: dict) -> tuple[str, str, str]:
    """Returns (event_type, severity, summary) for a decoy interaction.
    A credential attempt is the clearest possible signal (someone tried to
    log in to a service that doesn't exist for real) so it's always high;
    anything else structured is a probe worth a look; a bare connection with
    no logdata at all is the least specific signal OpenCanary can produce.
    """
    if "USERNAME" in logdata or "PASSWORD" in logdata:
        user = logdata.get("USERNAME", "?")
        password = logdata.get("PASSWORD", "?")
        return "credential_attempt", "high", f"login attempt: {user}/{password}"
    if "PATH" in logdata:
        return "http_probe", "medium", f"GET {logdata['PATH']}"
    if logdata:
        return "http_probe", "medium", ", ".join(f"{k}={v}" for k, v in logdata.items())
    return "connection", "low", "connection"


def _parse_event(line: str) -> SecurityEvent | None:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_host = entry.get("src_host") or ""
    if not src_host:
        return None  # housekeeping/startup line, not a real interaction

    dst_port = entry.get("dst_port", -1)
    logdata = entry.get("logdata") or {}
    event_type, severity, summary = _classify(logdata)
    service = SERVICE_NAMES.get(dst_port, f"port {dst_port}")

    return SecurityEvent(
        ts=entry.get("utc_time", ""),
        source="canary",
        event_type=event_type,
        severity=severity,
        target=src_host,
        service=service,
        summary=summary,
        detail={"dst_port": dst_port, "src_port": entry.get("src_port"), "logdata": logdata},
    )


async def collect(config: CanaryConfig) -> list[SecurityEvent]:
    if not config.enabled or not config.ssh_target:
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            config.ssh_target,
            f"tail -n {config.tail_lines} {config.log_path}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
    except (asyncio.TimeoutError, OSError):
        return []

    if proc.returncode != 0 or not stdout:
        return []

    events = [
        event
        for line in stdout.decode(errors="ignore").splitlines()
        if (event := _parse_event(line)) is not None
    ]
    events.sort(key=lambda e: e.ts, reverse=True)
    return events
