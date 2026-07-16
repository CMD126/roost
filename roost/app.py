from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Footer, Header

from .collectors import docker_containers, host, network, opencanary, portscan, uptime
from .config import AppConfig, load_config
from .models import CanaryAlert, NetworkDevice, PortScanResult
from .widgets.canary_panel import CanaryPanel
from .widgets.containers_panel import ContainersPanel
from .widgets.host_panel import HostPanel
from .widgets.network_panel import NetworkPanel
from .widgets.uptime_panel import UptimePanel


def _silence_proactor_connection_reset(loop: asyncio.AbstractEventLoop) -> None:
    """asyncio's Windows ProactorEventLoop logs a harmless traceback when a
    scanned host resets the connection while a transport is being torn down.
    It's cosmetic noise from the port scanner's nature (some services close
    abruptly after a banner), not a bug — suppress just that one case.
    """
    default_handler = loop.get_exception_handler()

    def handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        if isinstance(context.get("exception"), ConnectionResetError):
            return
        if default_handler is not None:
            default_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handler)

CSS = """
#body {
    height: 1fr;
}

#grid {
    layout: grid;
    grid-size: 2 2;
    grid-gutter: 1;
    grid-rows: 1fr 1fr;
    padding: 1 1 0 1;
    height: 65%;
}

CanaryPanel {
    height: 1fr;
    margin: 0 1 1 1;
}

ContainersPanel, HostPanel, UptimePanel, NetworkPanel, CanaryPanel {
    border: round $primary;
    padding: 0 1;
    height: 100%;
}

.panel-title {
    text-style: bold;
    color: $accent;
}

.panel-summary {
    color: $text-muted;
    margin-bottom: 1;
}

.meter-row {
    height: 1;
    margin-bottom: 1;
}

.meter-label {
    width: 10;
}
"""


class HomelabDashboard(App):
    """Terminal dashboard for a homelab: Docker, host, service uptime and LAN devices."""

    CSS = CSS
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_now", "Refresh now"),
    ]
    TITLE = "Roost"
    SUB_TITLE = "homelab dashboard"

    def __init__(self, config: AppConfig, config_path: Path) -> None:
        super().__init__()
        self.config = config
        self.config_path = config_path
        self._last_devices: list[NetworkDevice] = []
        self._last_portscan: dict[str, PortScanResult] = {}
        self._portscan_started = False
        self._seen_canary_keys: set[tuple] = set()
        self._canary_first_load = True

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="body"):
            with Container(id="grid"):
                yield ContainersPanel(id="containers-panel")
                host_source = (
                    self.config.host.remote.ssh_target if self.config.host.remote else "local"
                )
                yield HostPanel(id="host-panel", source_label=host_source)
                yield UptimePanel(id="uptime-panel")
                yield NetworkPanel(id="network-panel")
            yield CanaryPanel(id="canary-panel")
        yield Footer()

    def on_mount(self) -> None:
        _silence_proactor_connection_reset(asyncio.get_running_loop())

        if not self.config_path.exists():
            self.sub_title = f"no {self.config_path.name} found — using defaults"

        self.set_interval(self.config.refresh_interval, self._trigger_fast_refresh)
        self.set_interval(self.config.network.scan_interval, self._trigger_network_refresh)
        self.set_interval(self.config.network.portscan.interval, self._trigger_portscan_refresh)
        self.set_interval(self.config.canary.interval, self._trigger_canary_refresh)
        self._trigger_fast_refresh()
        self._trigger_network_refresh()
        self._trigger_canary_refresh()

    def action_refresh_now(self) -> None:
        self._trigger_fast_refresh()
        self._trigger_network_refresh()
        self._trigger_portscan_refresh()
        self._trigger_canary_refresh()

    def _trigger_fast_refresh(self) -> None:
        self.run_worker(self._refresh_fast(), exclusive=True, group="fast")

    def _trigger_network_refresh(self) -> None:
        self.run_worker(self._refresh_network(), exclusive=True, group="network")

    def _trigger_portscan_refresh(self) -> None:
        self.run_worker(self._refresh_portscan(), exclusive=True, group="portscan")

    def _trigger_canary_refresh(self) -> None:
        self.run_worker(self._refresh_canary(), exclusive=True, group="canary")

    async def _refresh_fast(self) -> None:
        docker_snapshot, host_metrics, uptime_results = await asyncio.gather(
            docker_containers.collect(self.config.docker),
            host.collect(self.config.host),
            uptime.collect(self.config.uptime),
        )
        self.query_one(ContainersPanel).update_data(docker_snapshot)
        self.query_one(HostPanel).update_data(host_metrics)
        self.query_one(UptimePanel).update_data(uptime_results)

    async def _refresh_network(self) -> None:
        self._last_devices = await network.collect(self.config.network)
        self._render_network_panel()
        # Give the exposure scan a head start on first contact instead of
        # making the user wait a full portscan.interval for any port data.
        if not self._portscan_started and self._last_devices:
            self._portscan_started = True
            self._trigger_portscan_refresh()

    async def _refresh_portscan(self) -> None:
        ips = [d.ip for d in self._last_devices]
        self._last_portscan = await portscan.scan_hosts(ips, self.config.network.portscan)
        self._render_network_panel()

    def _render_network_panel(self) -> None:
        self.query_one(NetworkPanel).update_data(self._last_devices, self._last_portscan)

    async def _refresh_canary(self) -> None:
        alerts: list[CanaryAlert] = await opencanary.collect(self.config.canary)
        current_keys = {a.key for a in alerts}

        if self._canary_first_load:
            # Don't flag the entire historical backlog as "new" on first open.
            new_keys: set[tuple] = set()
            self._canary_first_load = False
        else:
            new_keys = current_keys - self._seen_canary_keys
        self._seen_canary_keys |= current_keys

        self.query_one(CanaryPanel).update_data(alerts, new_keys)


def run(config_path: Path = Path("config.yaml")) -> None:
    config = load_config(config_path)
    # Mouse tracking is off: this app is keyboard-only (arrows, r, q), and
    # legacy terminals (e.g. Windows' old conhost.exe, as opposed to Windows
    # Terminal) leak raw mouse escape sequences as visible text instead of
    # consuming them when it's on.
    HomelabDashboard(config=config, config_path=config_path).run(mouse=False)
