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
class SecurityEvent:
    """One entry in the unified security log — either a real interaction
    with an OpenCanary honeypot service, or a network change (new device,
    a previously-closed port opening). Not a heuristic in either case: this
    is something that was actually observed, not a risk score.
    """

    ts: str  # UTC timestamp string
    source: str  # "canary" | "network"
    event_type: str  # "credential_attempt" | "http_probe" | "connection" | "new_device" | "device_returned" | "new_port"
    severity: str  # "high" | "medium" | "low"
    target: str  # src host (canary) or device ip (network)
    service: str
    summary: str
    detail: dict = field(default_factory=dict)
    status: str = "new"  # "new" | "acknowledged"

    @property
    def key(self) -> str:
        """Stable-enough identity for de-duplication and SQLite storage."""
        return f"{self.source}:{self.event_type}:{self.ts}:{self.target}:{self.service}:{self.summary}"


@dataclass(frozen=True)
class SocStats:
    """Rollup stats over the persisted event history."""

    total: int
    unacknowledged: int
    count_24h: int
    count_7d: int
    # Open (unacknowledged) counts by severity — what still needs a look,
    # not just a lifetime total.
    open_high: int = 0
    open_medium: int = 0
    open_low: int = 0
    last_event_ts: str | None = None
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_services: list[tuple[str, int]] = field(default_factory=list)
