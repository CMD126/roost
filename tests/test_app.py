from pathlib import Path

from roost.app import HomelabDashboard
from roost.config import AppConfig, NetworkConfig, UptimeConfig, UptimeTarget
from roost.widgets.containers_panel import ContainersPanel
from roost.widgets.host_panel import HostPanel
from roost.widgets.network_panel import NetworkPanel
from roost.widgets.uptime_panel import UptimePanel


def _fast_test_config() -> AppConfig:
    return AppConfig(
        refresh_interval=0.5,
        uptime=UptimeConfig(
            timeout=1.0,
            targets=[UptimeTarget(name="loopback", type="tcp", address="127.0.0.1", port=1)],
        ),
        network=NetworkConfig(cidr="127.0.0.0/30", scan_interval=0.5, timeout=1.0),
    )


async def test_app_mounts_all_panels_without_crashing():
    app = HomelabDashboard(config=_fast_test_config(), config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(1.5)

        assert app.query_one(ContainersPanel) is not None
        assert app.query_one(HostPanel) is not None
        assert app.query_one(UptimePanel) is not None
        assert app.query_one(NetworkPanel) is not None


async def test_refresh_binding_does_not_crash():
    app = HomelabDashboard(config=_fast_test_config(), config_path=Path("nonexistent.yaml"))
    async with app.run_test() as pilot:
        await pilot.pause(1.0)
        await pilot.press("r")
        await pilot.pause(1.0)
        assert app.is_running


async def test_missing_config_sets_fallback_subtitle():
    app = HomelabDashboard(config=_fast_test_config(), config_path=Path("nonexistent.yaml"))
    async with app.run_test():
        assert "nonexistent.yaml" in app.sub_title
