from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from .collectors import docker_containers, host, network, opencanary, portscan, uptime
from .config import AppConfig, ConfigError, load_config
from .models import NetworkDevice, PortScanResult, SecurityEvent
from .soc import SocStore, device_key
from .widgets.containers_panel import ContainersPanel
from .widgets.event_detail import Acknowledge
from .widgets.host_panel import HostPanel
from .widgets.network_panel import NetworkPanel
from .widgets.security_panel import SecurityPanel
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
/* One panel per tab, each filling the full screen below the tab bar — a
   cramped 2x2 grid left every DataTable with only ~20% of the terminal's
   height to work with, barely room to see a handful of rows let alone
   scroll through them comfortably. TabbedContent/ContentSwitcher/TabPane
   all default to height: auto (size-to-content), so each needs an explicit
   1fr override to actually fill the available space instead of collapsing.  */
TabbedContent {
    height: 1fr;
}

ContentSwitcher {
    height: 1fr;
}

TabPane {
    height: 1fr;
    padding: 0 1;
}

SecurityPanel, ContainersPanel, HostPanel, UptimePanel, NetworkPanel {
    height: 1fr;
    border: round $primary;
    padding: 0 1;
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
        # Direct tab jumps — deliberately independent of mouse and of which
        # widget currently has focus, so tab switching keeps working even on
        # a terminal where mouse/focus handling is flaky.
        ("1", "show_tab('tab-security')", "Security"),
        ("2", "show_tab('tab-network')", "Network"),
        ("3", "show_tab('tab-containers')", "Containers"),
        ("4", "show_tab('tab-host')", "Host"),
        ("5", "show_tab('tab-uptime')", "Uptime"),
    ]
    TITLE = "Roost"
    SUB_TITLE = "homelab dashboard"

    def __init__(self, config: AppConfig, config_path: Path) -> None:
        super().__init__()
        self.config = config
        self.config_path = config_path
        self.soc = SocStore(config_path.parent / config.events_db)
        self._last_devices: list[NetworkDevice] = []
        self._last_portscan: dict[str, PortScanResult] = {}
        self._new_device_ips: set[str] = set()
        self._portscan_started = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        host_source = self.config.host.remote.ssh_target if self.config.host.remote else "local"
        with TabbedContent(initial="tab-security"):
            with TabPane("Security Events", id="tab-security"):
                yield SecurityPanel(id="security-panel")
            with TabPane("Network", id="tab-network"):
                yield NetworkPanel(id="network-panel")
            with TabPane("Containers", id="tab-containers"):
                yield ContainersPanel(id="containers-panel")
            with TabPane("Host", id="tab-host"):
                yield HostPanel(id="host-panel", source_label=host_source)
            with TabPane("Uptime", id="tab-uptime"):
                yield UptimePanel(id="uptime-panel")
        yield Footer()

    # Maps each tab to the DataTable that should hold keyboard focus once it's
    # showing — the Host tab has no table (just meters) so it's left out.
    _TAB_FOCUS_TARGETS = {
        "tab-security": "#security-table",
        "tab-network": "#network-table",
        "tab-containers": "#containers-table",
        "tab-uptime": "#uptime-table",
    }

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id
        self._focus_tab_content(tab_id)

    def on_tabbed_content_tab_activated(self, message: TabbedContent.TabActivated) -> None:
        # Covers switching tabs by clicking a tab header directly (not just
        # the number-key shortcuts above) — same fix, same reason.
        self._focus_tab_content(message.pane.id or "")

    def _focus_tab_content(self, tab_id: str) -> None:
        # Switching the active tab only changes what's *visible* — Textual
        # doesn't move keyboard focus along with it. Left unfixed, focus
        # stays on the ContentTabs tab bar (which only understands left/right,
        # to move between tabs), so arrow keys/Enter inside the newly-shown
        # panel's table would silently do nothing until the user happened to
        # press Tab first.
        target_id = self._TAB_FOCUS_TARGETS.get(tab_id)
        if target_id is not None:
            self.query_one(target_id).focus()

    def on_mount(self) -> None:
        _silence_proactor_connection_reset(asyncio.get_running_loop())

        if not self.config_path.exists():
            self.sub_title = f"no {self.config_path.name} found — using defaults"

        self._focus_tab_content("tab-security")
        self.set_interval(self.config.refresh_interval, self._trigger_fast_refresh)
        self.set_interval(self.config.network.scan_interval, self._trigger_network_refresh)
        self.set_interval(self.config.network.portscan.interval, self._trigger_portscan_refresh)
        self.set_interval(self.config.canary.interval, self._trigger_canary_refresh)
        # Deferred, not called directly: TabbedContent mounts its ContentSwitcher
        # and TabPane children (including every panel) in its own nested compose
        # cycle, which doesn't necessarily finish before this on_mount runs. A
        # fast collector (e.g. a sub-millisecond loopback scan) could complete
        # and try to render into a panel that hadn't mounted yet, raising
        # NoMatches (caught by _guarded either way, but worth avoiding so the
        # dashboard has real data on the very first paint instead of waiting
        # out a full refresh_interval/scan_interval for the next retry).
        self.set_timer(0.1, self._trigger_fast_refresh)
        self.set_timer(0.1, self._trigger_network_refresh)
        self.set_timer(0.1, self._trigger_canary_refresh)

    def action_refresh_now(self) -> None:
        self._trigger_fast_refresh()
        self._trigger_network_refresh()
        self._trigger_portscan_refresh()
        self._trigger_canary_refresh()

    def _trigger_fast_refresh(self) -> None:
        self.run_worker(self._guarded(self._refresh_fast()), exclusive=True, group="fast")

    def _trigger_network_refresh(self) -> None:
        self.run_worker(self._guarded(self._refresh_network()), exclusive=True, group="network")

    def _trigger_portscan_refresh(self) -> None:
        self.run_worker(self._guarded(self._refresh_portscan()), exclusive=True, group="portscan")

    def _trigger_canary_refresh(self) -> None:
        self.run_worker(self._guarded(self._refresh_canary()), exclusive=True, group="canary")

    async def _guarded(self, coro) -> None:
        """Runs a refresh coroutine with a top-level safety net.

        Textual's own worker-exception handling always exits the whole app
        on an unhandled exception (App._handle_exception's own docstring says
        so) — so a bug anywhere in one panel's refresh (a collector, a
        query_one() racing a not-yet-mounted widget, anything) would kill the
        entire dashboard, not just that panel. Every refresh cycle is
        independent and safe to just skip and retry next interval, so this
        is the right place to make that failure mode local instead of fatal.
        """
        try:
            await coro
        except Exception as exc:
            self.log.error(f"refresh failed: {exc!r}")

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
        device_events = self.soc.record_device_snapshot(self._last_devices)
        self._new_device_ips = {e.target for e in device_events}
        self._render_network_panel()
        if device_events:
            self._render_security_panel()
        # Give the exposure scan a head start on first contact instead of
        # making the user wait a full portscan.interval for any port data.
        if not self._portscan_started and self._last_devices:
            self._portscan_started = True
            self._trigger_portscan_refresh()

    async def _refresh_portscan(self) -> None:
        ips = [d.ip for d in self._last_devices]
        self._last_portscan = await portscan.scan_hosts(ips, self.config.network.portscan)

        ip_to_key = {d.ip: device_key(d) for d in self._last_devices}
        port_events: list[SecurityEvent] = []
        for ip, result in self._last_portscan.items():
            port_events += self.soc.record_port_snapshot(ip_to_key.get(ip, ip), result.open_ports)

        self._render_network_panel()
        if port_events:
            self._render_security_panel()

    def _render_network_panel(self) -> None:
        self.query_one(NetworkPanel).update_data(self._last_devices, self._last_portscan, self._new_device_ips)

    async def _refresh_canary(self) -> None:
        events: list[SecurityEvent] = await opencanary.collect(self.config.canary)
        self.soc.record_events(events)
        self._render_security_panel()

    def _render_security_panel(self) -> None:
        self.query_one(SecurityPanel).update_data(self.soc.recent_events(), self.soc.stats())

    def on_acknowledge(self, message: Acknowledge) -> None:
        self.soc.set_status(message.key, "acknowledged")
        self._render_security_panel()


def run(config_path: Path = Path("config.yaml")) -> None:
    config = load_config(config_path)
    try:
        app = HomelabDashboard(config=config, config_path=config_path)
    except (OSError, sqlite3.Error) as exc:
        db_path = config_path.parent / config.events_db
        raise ConfigError(f"couldn't open events_db ({db_path}): {exc}") from exc
    app.run(mouse=config.mouse)
