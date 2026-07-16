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
from ..models import CanaryAlert
from .portscan import SERVICE_NAMES


def _format_summary(logdata: dict) -> str:
    if "USERNAME" in logdata or "PASSWORD" in logdata:
        user = logdata.get("USERNAME", "?")
        password = logdata.get("PASSWORD", "?")
        return f"login attempt: {user}/{password}"
    if "PATH" in logdata:
        return f"GET {logdata['PATH']}"
    if logdata:
        return ", ".join(f"{k}={v}" for k, v in logdata.items())
    return "connection"


def _parse_alert(line: str) -> CanaryAlert | None:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_host = entry.get("src_host") or ""
    if not src_host:
        return None  # housekeeping/startup line, not a real interaction

    dst_port = entry.get("dst_port", -1)
    logdata = entry.get("logdata") or {}
    return CanaryAlert(
        utc_time=entry.get("utc_time", ""),
        service=SERVICE_NAMES.get(dst_port, f"port {dst_port}"),
        src_host=src_host,
        dst_port=dst_port,
        summary=_format_summary(logdata),
    )


async def collect(config: CanaryConfig) -> list[CanaryAlert]:
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

    alerts = [
        alert
        for line in stdout.decode(errors="ignore").splitlines()
        if (alert := _parse_alert(line)) is not None
    ]
    alerts.sort(key=lambda a: a.utc_time, reverse=True)
    return alerts
