from __future__ import annotations

from textual.containers import Vertical
from textual.widgets import DataTable, Static

from ..models import CanaryAlert


class CanaryPanel(Vertical):
    """Real interactions with an OpenCanary honeypot — not heuristics, these
    are logged connections to a decoy service. Empty is the good outcome."""

    def compose(self):
        yield Static("ALERTS — OpenCanary", classes="panel-title")
        yield Static("", id="canary-summary", classes="panel-summary")
        yield DataTable(id="canary-table")

    def on_mount(self) -> None:
        table = self.query_one("#canary-table", DataTable)
        table.add_columns("New", "Time (UTC)", "Service", "Source IP", "Detail")
        table.cursor_type = "row"
        table.zebra_stripes = True

    def update_data(self, alerts: list[CanaryAlert], new_keys: set[tuple] | None = None) -> None:
        new_keys = new_keys or set()
        summary = self.query_one("#canary-summary", Static)
        table = self.query_one("#canary-table", DataTable)

        if not alerts:
            summary.update("[dim]No alerts seen — quiet, or the canary isn't enabled/running.[/]")
        else:
            new_note = f"   [red]{len(new_keys)} new since last refresh[/]" if new_keys else ""
            summary.update(f"[yellow]{len(alerts)}[/] alert(s) in the tail window{new_note}")

        table.clear()
        for alert in alerts[:200]:
            is_new = alert.key in new_keys
            marker = "[red]●[/]" if is_new else ""
            time_label = alert.utc_time.split(".")[0] or "—"
            table.add_row(marker, time_label, alert.service, alert.src_host, alert.summary)
