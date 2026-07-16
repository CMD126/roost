from __future__ import annotations

from textual.containers import Vertical
from textual.widgets import DataTable, Static

from ..models import UptimeResult


class UptimePanel(Vertical):
    """Reachability of configured services (HTTP / TCP / ping)."""

    def compose(self):
        yield Static("UPTIME", classes="panel-title")
        yield Static("", id="uptime-summary", classes="panel-summary")
        yield DataTable(id="uptime-table")

    def on_mount(self) -> None:
        table = self.query_one("#uptime-table", DataTable)
        table.add_columns("Service", "Status", "Latency", "Detail")
        table.cursor_type = "row"

    def update_data(self, results: list[UptimeResult]) -> None:
        summary = self.query_one("#uptime-summary", Static)
        table = self.query_one("#uptime-table", DataTable)

        if not results:
            summary.update("[dim]No targets configured[/]")
            table.clear()
            return

        up = sum(1 for r in results if r.up)
        summary.update(f"[green]{up} up[/] / {len(results) - up} down")

        table.clear()
        for r in results:
            status = "[green]● up[/]" if r.up else "[red]● down[/]"
            latency = f"{r.latency_ms:.0f} ms" if r.latency_ms is not None else "—"
            table.add_row(r.name, status, latency, r.detail)
