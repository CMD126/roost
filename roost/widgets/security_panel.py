from __future__ import annotations

from datetime import datetime, timezone

from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static
from textual.widgets.data_table import CellDoesNotExist, RowDoesNotExist
from textual.containers import Vertical

from ..models import SecurityEvent, SocStats
from ._clickable_table import ClickToSelectDataTable
from .event_detail import Acknowledge, EventDetailScreen

_SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "dim"}


def _time_ago(ts: str | None) -> str:
    if not ts:
        return "—"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            when = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    else:
        return "—"

    seconds = (datetime.now(timezone.utc) - when).total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


class SecurityPanel(Vertical):
    """The unified security event log: real OpenCanary interactions and
    network changes (new device, a previously-closed port opening) side by
    side, persisted across restarts. This is the dashboard's primary panel —
    a triage queue, not just a log: unacknowledged events lead, most recent
    first within that (chronological, not weighted by severity).

    Click (or select + Enter) a row for full detail; `a` acknowledges the
    selected event; `h` toggles hiding already-acknowledged ones.
    """

    BINDINGS = [
        ("a", "acknowledge", "Ack"),
        ("h", "toggle_hide_acknowledged", "Hide ack'd"),
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._events_by_key: dict[str, SecurityEvent] = {}
        self._all_events: list[SecurityEvent] = []
        self._stats: SocStats | None = None
        self._hide_acknowledged = False

    def compose(self):
        yield Static("SECURITY EVENTS", classes="panel-title")
        yield Static("", id="security-kpis", classes="panel-summary")
        yield Static("", id="security-stats", classes="panel-summary")
        yield ClickToSelectDataTable(id="security-table")

    def on_mount(self) -> None:
        table = self.query_one("#security-table", DataTable)
        table.add_columns("St", "Time (UTC)", "Sev", "Source", "Type", "Summary")
        table.cursor_type = "row"
        table.zebra_stripes = True

    def update_data(self, events: list[SecurityEvent], stats: SocStats) -> None:
        self._all_events = events
        self._stats = stats
        self._repaint()

    def _repaint(self) -> None:
        # Named _repaint, not _render: Widget._render() is a real Textual
        # internal method (part of the compositor pipeline) — shadowing it
        # with our own zero-arg update method silently breaks all rendering.
        stats = self._stats
        events = self._all_events
        if stats is None:
            return

        kpis = self.query_one("#security-kpis", Static)
        stats_line = self.query_one("#security-stats", Static)
        table = self.query_one("#security-table", DataTable)

        if not events:
            kpis.update("[dim]No security events recorded yet.[/]")
        else:
            severity_bits = []
            if stats.open_high:
                severity_bits.append(f"[red]{stats.open_high} HIGH[/]")
            if stats.open_medium:
                severity_bits.append(f"[yellow]{stats.open_medium} MEDIUM[/]")
            if stats.open_low:
                severity_bits.append(f"[dim]{stats.open_low} LOW[/]")
            severity_summary = "   ".join(severity_bits) if severity_bits else "[green]clear[/]"
            hidden_note = "   [dim](acknowledged hidden, press h to show)[/]" if self._hide_acknowledged else ""
            kpis.update(
                f"{severity_summary}   ·   [bold]{stats.unacknowledged}[/] open / {stats.total} total"
                f"   ·   last alert {_time_ago(stats.last_event_ts)}{hidden_note}"
            )

        top_src = ", ".join(f"{target} ({n})" for target, n in stats.top_sources) or "—"
        top_svc = ", ".join(f"{service} ({n})" for service, n in stats.top_services) or "—"
        stats_line.update(f"[dim]Top sources:[/] {top_src}    [dim]Top services:[/] {top_svc}")

        visible = [e for e in events if not (self._hide_acknowledged and e.status == "acknowledged")]
        self._events_by_key = {e.key: e for e in visible}

        previously_selected = self._selected_key()

        table.clear()
        for event in visible[:200]:
            color = _SEVERITY_COLOR.get(event.severity, "")
            marker = "[red]● NEW[/]" if event.status == "new" else "[dim]✓[/]"
            time_label = event.ts.split(".")[0] or "—"

            def cell(text: str) -> str:
                return f"[{color}]{text}[/]" if color else text

            table.add_row(
                marker, cell(time_label), cell(event.severity), cell(event.target),
                cell(event.event_type), cell(event.summary), key=event.key,
            )

        if previously_selected is not None:
            self._select_row_by_key(previously_selected)

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        event = self._events_by_key.get(message.row_key.value)
        if event is not None:
            self.app.push_screen(EventDetailScreen(event))

    def action_acknowledge(self) -> None:
        key = self._selected_key()
        if key is not None:
            self.post_message(Acknowledge(key))

    def action_toggle_hide_acknowledged(self) -> None:
        self._hide_acknowledged = not self._hide_acknowledged
        self._repaint()

    def _selected_key(self) -> str | None:
        table = self.query_one("#security-table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        except CellDoesNotExist:
            return None
        return row_key.value

    def _select_row_by_key(self, key: str) -> None:
        table = self.query_one("#security-table", DataTable)
        try:
            row_index = table.get_row_index(key)
        except RowDoesNotExist:
            return
        table.cursor_coordinate = Coordinate(row=row_index, column=0)
