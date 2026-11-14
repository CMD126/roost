"""Demo mode: the real dashboard fed with made-up data.

`roost --demo` runs the same App, widgets and SQLite event pipeline as a
normal session, but every data source is replaced with the canned values
below. Nothing is pinged, scanned or SSH'd into, and the events database
lives in a throwaway temp directory. It exists so the UI can be tried (and
the README screenshots regenerated) without a homelab or a honeypot.

All names, addresses and MACs here are invented. Attacker-side addresses use
the RFC 5737 documentation range 203.0.113.0/24.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .app import HomelabDashboard
from .config import AppConfig, NetworkConfig
from .models import (
    ContainerInfo,
    DockerSnapshot,
    HostMetrics,
    NetworkDevice,
    OpenPort,
    PortScanResult,
    SecurityEvent,
    UptimeResult,
)
from .soc import device_key

DEMO_LABEL = "demo mode: made-up data, nothing is scanned"


def _port(port: int, service: str, banner: str | None = None, risky: bool = False) -> OpenPort:
    return OpenPort(port=port, service=service, banner=banner, risky=risky)


# What the LAN looked like before this session: recorded and acknowledged at
# startup, so it shows up as already-triaged history.
_BASELINE_DEVICES = [
    NetworkDevice("192.168.1.1", "router.lan", 0.8, "02:00:5e:10:00:01", "Acme Networks"),
    NetworkDevice("192.168.1.10", "homelab-server.lan", 0.4, "02:00:5e:10:00:0a", "Example Systems"),
    NetworkDevice("192.168.1.20", "nas.lan", 0.6, "02:00:5e:10:00:14", "Example Storage"),
    NetworkDevice("192.168.1.31", "pi-hole.lan", 1.1, "b8:27:eb:10:00:1f", "Raspberry Pi Foundation"),
    NetworkDevice("192.168.1.50", "desktop.lan", 0.5, "02:00:5e:10:00:32", None),
]

_BASELINE_PORTS = {
    "192.168.1.1": [_port(53, "dns"), _port(80, "http", "lighttpd")],
    "192.168.1.10": [_port(22, "ssh", "SSH-2.0-OpenSSH_9.6"), _port(443, "https", "nginx")],
    "192.168.1.20": [_port(22, "ssh", "SSH-2.0-OpenSSH_9.2"), _port(445, "smb", risky=True)],
    "192.168.1.31": [_port(53, "dns"), _port(80, "http", "lighttpd/1.4.69")],
    "192.168.1.50": [],
}

# The "current" scan: one device nobody recognises has joined, and two
# previously-closed ports are now open.
_CURRENT_DEVICES = _BASELINE_DEVICES + [
    NetworkDevice("192.168.1.77", None, 3.2, "02:00:5e:10:00:4d", None),
]

_CURRENT_PORTS = {
    **_BASELINE_PORTS,
    "192.168.1.50": [_port(5900, "vnc", "RFB 003.008", risky=True)],
    "192.168.1.77": [
        _port(22, "ssh", "SSH-2.0-dropbear_2022.83"),
        _port(23, "telnet", risky=True),
        _port(8080, "http-alt", "GoAhead-Webs"),
    ],
}


def _canary_events(now: datetime) -> list[SecurityEvent]:
    def at(minutes_ago: float) -> str:
        return (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S.%f")

    def login(minutes_ago: float, src: str, service: str, port: int, user: str, password: str) -> SecurityEvent:
        return SecurityEvent(
            ts=at(minutes_ago), source="canary", event_type="credential_attempt", severity="high",
            target=src, service=service, summary=f"login attempt: {user}/{password}",
            detail={"dst_port": port, "src_port": 40000 + port, "logdata": {"USERNAME": user, "PASSWORD": password}},
        )

    return [
        login(2, "192.168.1.77", "ftp", 21, "admin", "admin"),
        login(3, "192.168.1.77", "ssh-alt", 2222, "root", "123456"),
        SecurityEvent(
            ts=at(4), source="canary", event_type="http_probe", severity="medium",
            target="192.168.1.77", service="http", summary="GET /cgi-bin/luci",
            detail={"dst_port": 80, "src_port": 51514, "logdata": {"PATH": "/cgi-bin/luci"}},
        ),
        SecurityEvent(
            ts=at(95), source="canary", event_type="connection", severity="low",
            target="203.0.113.45", service="telnet", summary="connection",
            detail={"dst_port": 23, "src_port": 61022, "logdata": {}},
        ),
    ]


_CONTAINERS = DockerSnapshot(available=True, error=None, containers=[
    ContainerInfo("grafana", "running", "grafana/grafana:11.1.0", 0.7, 142.0, 7834.0),
    ContainerInfo("home-assistant", "running", "homeassistant/home-assistant:2024.7", 3.4, 389.0, 7834.0),
    ContainerInfo("jellyfin", "running", "jellyfin/jellyfin:10.9.7", 1.9, 612.0, 7834.0),
    ContainerInfo("opencanary", "running", "thinkst/opencanary:latest", 0.2, 48.0, 7834.0),
    ContainerInfo("prometheus", "running", "prom/prometheus:v2.53.0", 1.2, 233.0, 7834.0),
    ContainerInfo("uptime-probe", "exited", "alpine:3.20", None, None, None),
])

_HOST = HostMetrics(
    cpu_percent=23.0, mem_percent=61.0, mem_used_gb=4.8, mem_total_gb=7.8,
    disk_percent=47.0, disk_used_gb=219.0, disk_total_gb=468.0,
    uptime_seconds=12 * 86400 + 5 * 3600 + 17 * 60, temperature_c=48.0,
)

_UPTIME = [
    UptimeResult("Router", "192.168.1.1:80", True, 1.0, "open"),
    UptimeResult("NAS web UI", "https://nas.lan", True, 14.0, "HTTP 200"),
    UptimeResult("Jellyfin", "http://192.168.1.10:8096/health", True, 9.0, "HTTP 200"),
    UptimeResult("Backup target", "192.168.1.60", False, None, "no reply"),
]


class DemoDashboard(HomelabDashboard):
    """HomelabDashboard with every collector replaced by the data above."""

    def __init__(self, events_dir: Path) -> None:
        config = AppConfig(
            events_db=str(events_dir / "demo_events.db"),
            network=NetworkConfig(cidr="192.168.1.0/24"),
        )
        super().__init__(config=config, config_path=events_dir / "demo.yaml")
        # Generated once, so every canary refresh returns events with the
        # same keys and they're de-duplicated instead of piling up.
        self._canary = _canary_events(datetime.now(timezone.utc))
        self._seed_history()

    def _seed_history(self) -> None:
        """Records the baseline LAN and acknowledges what it produced, as if
        those events had been triaged in an earlier session."""
        self.soc.record_device_snapshot(_BASELINE_DEVICES)
        for device in _BASELINE_DEVICES:
            self.soc.record_port_snapshot(device_key(device), _BASELINE_PORTS[device.ip], ip=device.ip)
        for event in self.soc.recent_events():
            self.soc.set_status(event.key, "acknowledged")

    # Not an on_mount override: Textual dispatches on_mount to every class in
    # the MRO, so overriding it here would run the parent's twice.
    def _startup_sub_title(self) -> str | None:
        return DEMO_LABEL

    async def _collect_fast(self):
        return _CONTAINERS, _HOST, _UPTIME

    async def _collect_devices(self) -> list[NetworkDevice]:
        return list(_CURRENT_DEVICES)

    async def _collect_portscan(self, ips: list[str]) -> dict[str, PortScanResult]:
        return {ip: PortScanResult(ip=ip, open_ports=_CURRENT_PORTS.get(ip, [])) for ip in ips}

    async def _collect_canary(self) -> list[SecurityEvent]:
        return list(self._canary)


def run_demo() -> None:
    with tempfile.TemporaryDirectory(prefix="roost-demo-") as tmp:
        app = DemoDashboard(Path(tmp))
        try:
            app.run()
        finally:
            app.soc.close()
