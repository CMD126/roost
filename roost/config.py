"""Loads config.yaml (falling back to sane defaults when it's missing)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path("config.yaml")


class ConfigError(Exception):
    """A config.yaml that fails to parse, or is missing/mistyping a required
    field. Caught in __main__ to print a clean one-line message instead of a
    raw traceback — a config typo is common and shouldn't look like a crash.
    """


@dataclass(frozen=True)
class UptimeTarget:
    name: str
    type: str  # "http" | "tcp" | "ping"
    address: str = ""
    url: str = ""
    port: int = 0


@dataclass(frozen=True)
class UptimeConfig:
    enabled: bool = True
    timeout: float = 3.0
    targets: list[UptimeTarget] = field(default_factory=list)


DEFAULT_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8080, 8443, 9000, 9090, 9200, 27017, 32400,
]


@dataclass(frozen=True)
class PortScanConfig:
    enabled: bool = True
    interval: float = 300.0
    timeout: float = 1.5
    concurrency: int = 64
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_SCAN_PORTS))


@dataclass(frozen=True)
class NetworkConfig:
    enabled: bool = True
    cidr: str = ""
    scan_interval: float = 60.0
    timeout: float = 1.0
    concurrency: int = 32
    portscan: PortScanConfig = field(default_factory=PortScanConfig)


@dataclass(frozen=True)
class DockerConfig:
    enabled: bool = True
    host: str | None = None


@dataclass(frozen=True)
class RemoteHostConfig:
    ssh_target: str
    python: str = "python3"


@dataclass(frozen=True)
class HostConfig:
    enabled: bool = True
    # When set, host metrics are collected over SSH from this machine instead
    # of the machine running the dashboard.
    remote: RemoteHostConfig | None = None


@dataclass(frozen=True)
class CanaryConfig:
    # Off by default — it only makes sense once you've actually deployed
    # OpenCanary (or a compatible JSON-lines logger) somewhere.
    enabled: bool = False
    ssh_target: str = ""
    log_path: str = "/var/tmp/opencanary.log"
    tail_lines: int = 200
    interval: float = 30.0


@dataclass(frozen=True)
class AppConfig:
    refresh_interval: float = 5.0
    # Mouse support — on by default. Only turn this off on a legacy Windows
    # console (conhost.exe, not Windows Terminal) that leaks raw mouse
    # escape sequences as visible text instead of consuming them.
    mouse: bool = True
    docker: DockerConfig = field(default_factory=DockerConfig)
    host: HostConfig = field(default_factory=HostConfig)
    uptime: UptimeConfig = field(default_factory=UptimeConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    canary: CanaryConfig = field(default_factory=CanaryConfig)
    # SQLite file backing the Security Events panel's history/triage state,
    # resolved relative to the config file's directory (same convention as
    # config.yaml itself).
    events_db: str = "roost_events.db"


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    if not path.exists():
        return AppConfig()

    try:
        return _parse_config(path)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    except (KeyError, TypeError, AttributeError) as exc:
        # Covers both an explicitly-missing required field (KeyError, e.g. an
        # uptime target with no `name`) and a wrong-shaped section (e.g.
        # `docker: true` instead of a mapping, which makes the next
        # `.get(...)` call raise AttributeError/TypeError) — there are too
        # many ways a hand-edited YAML file can be malformed to enumerate
        # them all, so this boundary degrades any of them to one clear
        # message rather than a raw traceback.
        raise ConfigError(f"{path} has an invalid or incomplete section ({exc})") from exc


def _parse_config(path: Path) -> AppConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping (key: value pairs) at the top level")

    docker_raw = raw.get("docker", {}) or {}
    host_raw = raw.get("host", {}) or {}
    uptime_raw = raw.get("uptime", {}) or {}
    network_raw = raw.get("network", {}) or {}

    targets = []
    for i, t in enumerate(uptime_raw.get("targets", [])):
        for required in ("name", "type"):
            if required not in t:
                raise ConfigError(
                    f"uptime.targets[{i}] ({t.get('name', '?')!r}) is missing required field '{required}'"
                )
        targets.append(UptimeTarget(
            name=t["name"],
            type=t["type"],
            address=t.get("address", ""),
            url=t.get("url", ""),
            port=t.get("port", 0),
        ))

    return AppConfig(
        refresh_interval=raw.get("refresh_interval", 5.0),
        mouse=raw.get("mouse", True),
        events_db=raw.get("events_db", "roost_events.db"),
        docker=DockerConfig(
            enabled=docker_raw.get("enabled", True),
            host=docker_raw.get("host"),
        ),
        host=HostConfig(
            enabled=host_raw.get("enabled", True),
            remote=(
                RemoteHostConfig(
                    ssh_target=host_raw["remote"]["ssh_target"],
                    python=host_raw["remote"].get("python", "python3"),
                )
                if host_raw.get("remote")
                else None
            ),
        ),
        uptime=UptimeConfig(
            enabled=uptime_raw.get("enabled", True),
            timeout=uptime_raw.get("timeout", 3.0),
            targets=targets,
        ),
        network=_load_network_config(network_raw),
        canary=_load_canary_config(raw.get("canary", {}) or {}),
    )


def _load_canary_config(canary_raw: dict) -> CanaryConfig:
    return CanaryConfig(
        enabled=canary_raw.get("enabled", False),
        ssh_target=canary_raw.get("ssh_target", ""),
        log_path=canary_raw.get("log_path", "/var/tmp/opencanary.log"),
        tail_lines=canary_raw.get("tail_lines", 200),
        interval=canary_raw.get("interval", 30.0),
    )


def _load_network_config(network_raw: dict) -> NetworkConfig:
    portscan_raw = network_raw.get("portscan", {}) or {}
    return NetworkConfig(
        enabled=network_raw.get("enabled", True),
        cidr=network_raw.get("cidr", ""),
        scan_interval=network_raw.get("scan_interval", 60.0),
        timeout=network_raw.get("timeout", 1.0),
        concurrency=network_raw.get("concurrency", 32),
        portscan=PortScanConfig(
            enabled=portscan_raw.get("enabled", True),
            interval=portscan_raw.get("interval", 300.0),
            timeout=portscan_raw.get("timeout", 1.5),
            concurrency=portscan_raw.get("concurrency", 64),
            ports=portscan_raw.get("ports", list(DEFAULT_SCAN_PORTS)),
        ),
    )
