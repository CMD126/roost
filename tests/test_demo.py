import pytest
from textual.widgets import DataTable

from roost.collectors import docker_containers, host, network, opencanary, portscan, uptime
from roost.demo import DEMO_LABEL, DemoDashboard
from roost.widgets.security_panel import SecurityPanel


@pytest.fixture
def no_real_collectors(monkeypatch):
    """Demo mode must never touch the network: make every real collector fail loudly."""
    def forbidden(*_args, **_kwargs):
        raise AssertionError("demo mode called a real collector")

    for module, name in [
        (docker_containers, "collect"), (host, "collect"), (uptime, "collect"),
        (network, "collect"), (portscan, "scan_hosts"), (opencanary, "collect"),
    ]:
        monkeypatch.setattr(module, name, forbidden)


async def test_demo_populates_every_panel_without_real_collectors(tmp_path, no_real_collectors):
    app = DemoDashboard(tmp_path)
    async with app.run_test(size=(132, 36)) as pilot:
        await app._refresh_fast()
        await app._refresh_network()
        await app._refresh_portscan()
        await app._refresh_canary()
        await pilot.pause(0.3)

        assert app.sub_title == DEMO_LABEL
        assert app.query_one("#containers-table", DataTable).row_count > 0
        assert app.query_one("#uptime-table", DataTable).row_count > 0
        assert app.query_one("#network-table", DataTable).row_count > 0

        events = app.soc.recent_events()
        statuses = {e.status for e in events}
        assert statuses == {"new", "acknowledged"}  # live alerts on top of triaged history
        assert {e.source for e in events if e.status == "new"} == {"canary", "network"}
        assert app.query_one(SecurityPanel).query_one("#security-table", DataTable).row_count == len(events)
        assert app._exception is None
    app.soc.close()


async def test_demo_canary_refresh_does_not_duplicate_events(tmp_path, no_real_collectors):
    def canary_count() -> int:
        return sum(1 for e in app.soc.recent_events() if e.source == "canary")

    app = DemoDashboard(tmp_path)
    async with app.run_test() as pilot:
        await app._refresh_canary()
        first = canary_count()
        await app._refresh_canary()
        await pilot.pause(0.1)
        assert first > 0
        assert canary_count() == first
    app.soc.close()
