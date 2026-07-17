"""Collects container state from a Docker daemon (local or remote)."""

from __future__ import annotations

import asyncio

import docker
from docker.errors import DockerException

from ..config import DockerConfig
from ..models import ContainerInfo, DockerSnapshot

_BYTES_PER_MB = 1024 * 1024


def _cpu_percent(stats: dict) -> float | None:
    try:
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"]["system_cpu_usage"]
            - stats["precpu_stats"]["system_cpu_usage"]
        )
        online_cpus = stats["cpu_stats"].get("online_cpus") or len(
            stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1]
        )
        if system_delta <= 0 or cpu_delta < 0:
            return 0.0
        return (cpu_delta / system_delta) * online_cpus * 100.0
    except (KeyError, ZeroDivisionError, TypeError):
        return None


def _collect_sync(config: DockerConfig) -> DockerSnapshot:
    try:
        client = (
            docker.DockerClient(base_url=config.host)
            if config.host
            else docker.from_env()
        )
        client.ping()
    except Exception as exc:
        # A remote docker.host (ssh:// or tcp://) can fail below docker-py's
        # own exception layer in ways that aren't a DockerException at all —
        # a plain OSError from the raw socket (connection refused, blocked
        # by a firewall), or paramiko's own SSHException hierarchy (bad
        # banner, auth failure, protocol negotiation failure). Trying to
        # enumerate every exception type a remote transport can leak is a
        # losing game — this boundary is documented to degrade gracefully,
        # never crash the app, so it catches broadly on purpose.
        return DockerSnapshot(available=False, error=str(exc))

    containers: list[ContainerInfo] = []
    try:
        for c in client.containers.list(all=True):
            cpu_pct = None
            mem_used_mb = None
            mem_limit_mb = None
            if c.status == "running":
                try:
                    stats = c.stats(stream=False)
                    cpu_pct = _cpu_percent(stats)
                    mem = stats.get("memory_stats", {})
                    if mem.get("usage") is not None:
                        mem_used_mb = mem["usage"] / _BYTES_PER_MB
                    if mem.get("limit"):
                        mem_limit_mb = mem["limit"] / _BYTES_PER_MB
                except DockerException:
                    pass

            try:
                image = c.image.tags[0] if c.image.tags else c.image.short_id
            except DockerException:
                # The image backing a container can be removed later (e.g.
                # `docker image prune`) while the container itself still
                # exists — one container's dangling image reference shouldn't
                # take down the whole panel, just that one field.
                image = "unknown"

            containers.append(
                ContainerInfo(
                    name=c.name,
                    status=c.status,
                    image=image,
                    cpu_percent=cpu_pct,
                    mem_usage_mb=mem_used_mb,
                    mem_limit_mb=mem_limit_mb,
                )
            )
    except Exception as exc:
        return DockerSnapshot(available=False, error=str(exc))
    finally:
        client.close()

    containers.sort(key=lambda c: c.name.lower())
    return DockerSnapshot(available=True, error=None, containers=containers)


async def collect(config: DockerConfig) -> DockerSnapshot:
    """Runs the blocking docker-py calls off the event loop."""
    if not config.enabled:
        return DockerSnapshot(available=False, error="disabled")
    return await asyncio.to_thread(_collect_sync, config)
