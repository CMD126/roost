"""Collects CPU, memory, disk and temperature — either for the machine running
the dashboard, or, when `host.remote` is configured, for a remote machine
reached over SSH (reusing whatever `python3` + `psutil` is available there).
"""

from __future__ import annotations

import asyncio
import base64
import json
import time

import psutil

from ..config import HostConfig, RemoteHostConfig
from ..models import HostMetrics

_GB = 1024 ** 3

# Runs standalone on the remote host: no dependency on this package being
# installed there, only psutil (already required if it's running our own venv).
_REMOTE_SCRIPT = """
import json, time
import psutil

mem = psutil.virtual_memory()
disk = psutil.disk_usage("/")
temp = None
try:
    for entries in (psutil.sensors_temperatures() or {}).values():
        for entry in entries:
            if entry.current:
                temp = float(entry.current)
                break
        if temp is not None:
            break
except (OSError, AttributeError):
    pass

print(json.dumps({
    "cpu_percent": psutil.cpu_percent(interval=0.3),
    "mem_percent": mem.percent,
    "mem_used_gb": mem.used / (1024 ** 3),
    "mem_total_gb": mem.total / (1024 ** 3),
    "disk_percent": disk.percent,
    "disk_used_gb": disk.used / (1024 ** 3),
    "disk_total_gb": disk.total / (1024 ** 3),
    "uptime_seconds": time.time() - psutil.boot_time(),
    "temperature_c": temp,
}))
""".strip()


def _read_temperature_c() -> float | None:
    # Not available on Windows, and not every Linux kernel exposes sensors either.
    sensors_fn = getattr(psutil, "sensors_temperatures", None)
    if sensors_fn is None:
        return None
    try:
        readings = sensors_fn()
    except (OSError, AttributeError):
        return None
    for entries in readings.values():
        for entry in entries:
            if entry.current:
                return float(entry.current)
    return None


def _collect_sync() -> HostMetrics:
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return HostMetrics(
        cpu_percent=psutil.cpu_percent(interval=0.3),
        mem_percent=mem.percent,
        mem_used_gb=mem.used / _GB,
        mem_total_gb=mem.total / _GB,
        disk_percent=disk.percent,
        disk_used_gb=disk.used / _GB,
        disk_total_gb=disk.total / _GB,
        uptime_seconds=time.time() - psutil.boot_time(),
        temperature_c=_read_temperature_c(),
    )


async def _collect_remote(remote: RemoteHostConfig) -> HostMetrics | None:
    encoded = base64.b64encode(_REMOTE_SCRIPT.encode()).decode()
    remote_cmd = f"{remote.python} -c 'import base64;exec(base64.b64decode(\"{encoded}\"))'"

    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            remote.ssh_target,
            remote_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except (asyncio.TimeoutError, OSError):
        return None

    if proc.returncode != 0 or not stdout:
        return None

    try:
        data = json.loads(stdout.decode())
        return HostMetrics(**data)
    except (json.JSONDecodeError, TypeError):
        return None


async def collect(config: HostConfig) -> HostMetrics | None:
    if not config.enabled:
        return None
    if config.remote is not None:
        return await _collect_remote(config.remote)
    return await asyncio.to_thread(_collect_sync)
