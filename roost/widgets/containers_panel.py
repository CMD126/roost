from __future__ import annotations

from textual.containers import Vertical
from textual.widgets import DataTable, Static

from ..models import DockerSnapshot


class ContainersPanel(Vertical):
    """Docker container status, CPU and memory usage."""

    def compose(self):
        yield Static("CONTAINERS", classes="panel-title")
        yield Static("", id="containers-summary", classes="panel-summary")
        yield DataTable(id="containers-table")

    def on_mount(self) -> None:
        table = self.query_one("#containers-table", DataTable)
        table.add_columns("Name", "Status", "Image", "CPU %", "Mem (MB)")
        table.cursor_type = "row"

    def update_data(self, snapshot: DockerSnapshot) -> None:
        summary = self.query_one("#containers-summary", Static)
        table = self.query_one("#containers-table", DataTable)

        if not snapshot.available:
            summary.update(f"[red]Docker unavailable:[/] {snapshot.error or 'disabled'}")
            table.clear()
            return

        up = sum(1 for c in snapshot.containers if c.is_up)
        total = len(snapshot.containers)
        summary.update(f"[green]{up} up[/] / {total - up} down / {total} total")

        table.clear()
        for c in snapshot.containers:
            status = f"[green]{c.status}[/]" if c.is_up else f"[red]{c.status}[/]"
            cpu = f"{c.cpu_percent:.1f}" if c.cpu_percent is not None else "—"
            mem = f"{c.mem_usage_mb:.0f}" if c.mem_usage_mb is not None else "—"
            table.add_row(c.name, status, c.image, cpu, mem)
