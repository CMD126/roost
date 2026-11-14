from pathlib import Path

import pytest
from textual.widgets import DataTable, TabbedContent

from roost.app import HomelabDashboard, run
from roost.collectors import network, portscan
from roost.config import AppConfig, ConfigError, DockerConfig, NetworkConfig, UptimeConfig, UptimeTarget
from roost.models import NetworkDevice
from roost.widgets.containers_panel import ContainersPanel
from roost.widgets.event_detail import EventDetailScreen
from roost.widgets.host_panel import HostPanel
from roost.widgets.network_panel import NetworkPanel
from roost.widgets.security_panel import SecurityPanel
from roost.widgets.uptime_panel import UptimePanel


def _fast_test_config(events_db: str) -> AppConfig:
    return AppConfig(
        refresh_interval=0.5,
        events_db=events_db,
        uptime=UptimeConfig(
            timeout=1.0,
            targets=[UptimeTarget(name="loopback", type="tcp", address="127.0.0.1", port=1)],
        ),
        network=NetworkConfig(cidr="127.0.0.0/30", scan_interval=0.5, timeout=1.0),
    )


async def test_app_mounts_all_panels_without_crashing(tmp_path):
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(1.5)

        assert app.query_one(ContainersPanel) is not None
        assert app.query_one(HostPanel) is not None
        assert app.query_one(UptimePanel) is not None
        assert app.query_one(NetworkPanel) is not None
        assert app.query_one(SecurityPanel) is not None


async def test_refresh_binding_does_not_crash(tmp_path):
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(1.0)
        await pilot.press("r")
        await pilot.pause(1.0)
        assert app.is_running


async def test_missing_config_sets_fallback_subtitle(tmp_path):
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test():
        assert "nonexistent.yaml" in app.sub_title


async def test_security_table_single_click_opens_exactly_one_modal(tmp_path, monkeypatch):
    # Regression test: Textual's message dispatch invokes _on_click from
    # every class in the MRO, not just the most-derived override, so a
    # naive ClickToSelectDataTable that both moves the cursor *and* posts
    # its own RowSelected caused DataTable's own _on_click to post a second
    # one right behind it — one click silently stacked two modal screens.
    #
    # The table needs at least one row to click on. Seed it with a fake
    # "new device" discovery rather than a real ICMP sweep of loopback,
    # which silently finds nothing on hosts/CI runners without ping.
    async def fake_network_collect(_config):
        return [NetworkDevice(ip="127.0.0.1", hostname="localhost", latency_ms=0.1)]

    async def fake_scan_hosts(_ips, _config):
        return {}

    monkeypatch.setattr(network, "collect", fake_network_collect)
    monkeypatch.setattr(portscan, "scan_hosts", fake_scan_hosts)
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause(0.2)
        await app._refresh_network()  # deterministic: don't race the interval timer
        await pilot.pause(0.3)

        table = app.query_one(SecurityPanel).query_one("#security-table", DataTable)
        assert table.row_count >= 1

        await pilot.click("#security-table", offset=(2, 1))
        await pilot.pause(0.3)

        assert len(app.screen_stack) == 2, "single click should open exactly one modal"
        assert isinstance(app.screen, EventDetailScreen)

        await pilot.press("escape")
        await pilot.pause(0.3)
        assert len(app.screen_stack) == 1, "escape should return fully to the dashboard"


async def test_number_key_switches_active_tab(tmp_path):
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(0.3)
        tabs = app.query_one(TabbedContent)
        assert tabs.active == "tab-security"

        await pilot.press("2")
        await pilot.pause(0.2)
        assert tabs.active == "tab-network"

        await pilot.press("3")
        await pilot.pause(0.2)
        assert tabs.active == "tab-containers"

        await pilot.press("1")
        await pilot.pause(0.2)
        assert tabs.active == "tab-security"


async def test_switching_tabs_moves_keyboard_focus_into_the_new_panel(tmp_path):
    # Regression: TabbedContent.active only changes what's *visible* —
    # Textual doesn't move keyboard focus along with it. Left unfixed, focus
    # stayed on the ContentTabs tab bar (which only understands left/right),
    # so arrow keys inside the newly-shown panel's table silently did
    # nothing — exactly what looked like "navigation is broken" from the
    # user's side after the tabbed-layout redesign.
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(0.3)
        assert app.focused is not None and app.focused.id == "security-table"

        await pilot.press("2")
        await pilot.pause(0.2)
        assert app.focused is not None and app.focused.id == "network-table"

        table = app.query_one(NetworkPanel).query_one("#network-table", DataTable)
        # Loopback range gives at least one row even without waiting for the
        # network scan to finish (row_count may be 0 briefly, but the cursor
        # attribute and focus behavior don't depend on that).
        before = table.cursor_row
        await pilot.press("down")
        await pilot.pause(0.1)
        # Cursor only moves if there are rows to move into; the real
        # assertion is that arrow keys reach the table at all (no exception,
        # and focus — checked above — is actually on it).
        assert table.cursor_row >= before


async def test_refresh_worker_exception_does_not_crash_whole_app(tmp_path, monkeypatch):
    # Regression: Textual's own App._handle_exception exits the *entire* app
    # on any unhandled worker exception (its docstring says so outright) — so
    # a bug in a single panel's refresh (a collector, a query_one() racing a
    # not-yet-mounted widget after the tabbed-layout redesign, anything)
    # would previously take down the whole dashboard, not just that panel.
    # _guarded() is the safety net that makes a refresh failure local instead
    # of fatal; this proves it actually holds.
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))

    async def boom():
        raise RuntimeError("simulated refresh failure")

    monkeypatch.setattr(app, "_refresh_fast", boom)
    async with app.run_test() as pilot:
        await pilot.pause(1.0)
        assert app.is_running
        assert app._exception is None


def test_run_raises_config_error_for_unwritable_events_db(tmp_path):
    # A plain file where a directory component is expected makes
    # mkdir(parents=True) raise NotADirectoryError (a real, portable way to
    # force the failure without relying on OS permission semantics) — this
    # must surface as one clear ConfigError before the TUI ever launches,
    # not a raw traceback from deep inside SocStore/sqlite3.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"events_db: '{blocker}/sub/events.db'\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="couldn't open events_db"):
        run(config_path=config_path)


# Markup-looking strings an attacker fully controls: a username typed into a
# honeypot login prompt, a service banner, a reverse-DNS name. Each one used
# to be interpolated into a Rich/Textual markup string; "[/]" alone raised
# MarkupError at render time and exited the whole dashboard.
_HOSTILE_STRINGS = ["[/]", "[bold", "[link=http://evil.example]click[/link]", "[red]fake[/red]"]


def _quiet_config(events_db: str) -> AppConfig:
    """No background collector produces rows, so a test controls every one."""
    return AppConfig(
        events_db=events_db,
        docker=DockerConfig(enabled=False),
        uptime=UptimeConfig(enabled=False),
        network=NetworkConfig(enabled=False),
    )


@pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
async def test_hostile_honeypot_input_is_shown_verbatim_and_does_not_crash(tmp_path, monkeypatch, hostile):
    from roost.collectors import opencanary
    from roost.models import SecurityEvent

    async def fake_canary_collect(_config):
        return [SecurityEvent(
            ts="2026-07-01 10:00:00.000000", source="canary", event_type="credential_attempt",
            severity="high", target="203.0.113.7", service="ftp",
            summary=f"login attempt: {hostile}/{hostile}", detail={"logdata": {"USERNAME": hostile}},
        )]

    monkeypatch.setattr(opencanary, "collect", fake_canary_collect)
    config = _quiet_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test(size=(140, 40)) as pilot:
        await app._refresh_canary()
        await pilot.pause(0.3)

        table = app.query_one(SecurityPanel).query_one("#security-table", DataTable)
        assert table.row_count == 1
        summary_cell = table.get_row_at(0)[-1]
        assert str(summary_cell) == f"login attempt: {hostile}/{hostile}"

        await pilot.press("enter")
        await pilot.pause(0.3)
        assert isinstance(app.screen, EventDetailScreen)
        assert app.is_running
    assert app._exception is None


@pytest.mark.parametrize("hostile", _HOSTILE_STRINGS)
async def test_hostile_banner_and_hostname_render_verbatim(tmp_path, monkeypatch, hostile):
    from roost.models import OpenPort, PortScanResult

    device = NetworkDevice(ip="192.168.1.20", hostname=hostile, latency_ms=1.0)
    scan = {"192.168.1.20": PortScanResult(ip="192.168.1.20", open_ports=[
        OpenPort(port=22, service="ssh", banner=hostile, risky=False),
    ])}

    async def fake_network_collect(_config):
        return [device]

    async def fake_scan_hosts(_ips, _config):
        return scan

    monkeypatch.setattr(network, "collect", fake_network_collect)
    monkeypatch.setattr(portscan, "scan_hosts", fake_scan_hosts)
    config = _fast_test_config(str(tmp_path / "events.db"))
    app = HomelabDashboard(config=config, config_path=Path("nonexistent.yaml"))
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.press("2")
        await app._refresh_network()
        await app._refresh_portscan()
        await pilot.pause(0.3)
        panel = app.query_one(NetworkPanel)
        # The table registers new rows on its next idle; redraw the detail
        # once the cursor actually sits on the device row.
        panel._update_detail()
        await pilot.pause(0.1)

        detail = str(panel.query_one("#network-detail").render())
        assert f"192.168.1.20 ({hostile})" in detail
        assert f"22/ssh  {hostile}" in detail
        table = panel.query_one("#network-table", DataTable)
        assert str(table.get_row_at(0)[2]) == hostile
        assert app.is_running
    assert app._exception is None
