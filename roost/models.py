"""Typed results produced by the collectors and consumed by the widgets."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ContainerInfo:
    name: str
    status: str
    image: str
    cpu_percent: float | None
    mem_usage_mb: float | None
    mem_limit_mb: float | None

    @property
    def is_up(self) -> bool:
        return self.status == "running"


@dataclass(frozen=True)
class DockerSnapshot:
    available: bool
    error: str | None
    containers: list[ContainerInfo] = field(default_factory=list)


@dataclass(frozen=True)
class HostMetrics:
    cpu_percent: float
    mem_percent: float
    mem_used_gb: float
    mem_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    uptime_seconds: float
    temperature_c: float | None


@dataclass(frozen=True)
class UptimeResult:
    name: str
    address: str
    up: bool
    latency_ms: float | None
    detail: str


@dataclass(frozen=True)
class NetworkDevice:
    ip: str
    hostname: str | None
    latency_ms: float | None
    mac: str | None = None
    vendor: str | None = None


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str
    banner: str | None
    risky: bool


@dataclass(frozen=True)
class PortScanResult:
    ip: str
    open_ports: list[OpenPort] = field(default_factory=list)


@dataclass(frozen=True)
class CanaryAlert:
    """A single real interaction with an OpenCanary honeypot service —
    someone (or something) touched a decoy, this is not a heuristic.
    """

    utc_time: str
    service: str
    src_host: str
    dst_port: int
    summary: str

    @property
    def key(self) -> tuple[str, str, int, str]:
        """Stable-enough identity for de-duplication and "is this new" checks."""
        return (self.utc_time, self.src_host, self.dst_port, self.summary)
