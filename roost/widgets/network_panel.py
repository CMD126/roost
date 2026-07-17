from __future__ import annotations

from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static
from textual.widgets.data_table import CellDoesNotExist, RowDoesNotExist
from textual.containers import Vertical

from ..models import NetworkDevice, PortScanResult


def _format_exposure_badge(result: PortScanResult | None) -> str:
    if result is None:
        return "[dim]…[/]"
    if not result.open_ports:
        return "[dim]none[/]"
    risky = sum(1 for p in result.open_ports if p.risky)
    total = len(result.open_ports)
    return f"[red]{total} open ({risky}⚠)[/]" if risky else f"{total} open"


def _format_ports_detail(result: PortScanResult | None) -> str:
    if result is None:
        return "[dim]Scanning…[/]"
    if not result.open_ports:
        return "[dim]No open ports found.[/]"
    lines = []
    for p in result.open_ports:
        marker = "[red]⚠[/]" if p.risky else " "
        banner = f"  {p.banner}" if p.banner else ""
        lines.append(f"{marker} {p.port}/{p.service}{banner}")
    return "\n".join(lines)


class NetworkPanel(Vertical):
    """Devices found on the LAN, with MAC/vendor identification. The table
    stays compact (one exposure badge per row) — select a row to see its
    full open-port breakdown below, instead of cramming everything inline.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._devices: list[NetworkDevice] = []
        self._portscan_results: dict[str, PortScanResult] = {}
        self._new_ips: set[str] = set()

    def compose(self):
        yield Static("NETWORK", classes="panel-title")
        yield Static("", id="network-summary", classes="panel-summary")
        yield DataTable(id="network-table")
        yield Static(
            "[dim]Select a device (↑/↓) to see its open ports.[/]",
            id="network-detail",
            classes="panel-summary",
        )

    def on_mount(self) -> None:
        table = self.query_one("#network-table", DataTable)
        table.add_columns("New", "IP", "Name", "Vendor", "Latency", "Exposure")
        table.cursor_type = "row"

    def update_data(
        self,
        devices: list[NetworkDevice],
        portscan_results: dict[str, PortScanResult] | None = None,
        new_ips: set[str] | None = None,
    ) -> None:
        self._devices = devices
        self._portscan_results = portscan_results or {}
        # Only flags devices new in *this* scan cycle — the persistent
        # history/detail view for these lives in the Security Events panel.
        self._new_ips = new_ips or set()

        summary = self.query_one("#network-summary", Static)
        table = self.query_one("#network-table", DataTable)

        risky_count = sum(
            1 for r in self._portscan_results.values() for p in r.open_ports if p.risky
        )
        risky_note = f"   [red]{risky_count} risky port(s)[/]" if risky_count else ""
        summary.update(f"[green]{len(devices)}[/] devices online{risky_note}")

        previously_selected = self._selected_ip()

        table.clear()
        for d in devices:
            marker = "[red]●[/]" if d.ip in self._new_ips else ""
            latency = f"{d.latency_ms:.0f} ms" if d.latency_ms is not None else "—"
            name = d.hostname or d.vendor or "—"
            vendor = d.vendor or "—"
            exposure = _format_exposure_badge(self._portscan_results.get(d.ip))
            table.add_row(marker, d.ip, name, vendor, latency, exposure, key=d.ip)

        if previously_selected is not None:
            self._select_row_by_ip(previously_selected)
        self._update_detail()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._update_detail()

    def _selected_ip(self) -> str | None:
        table = self.query_one("#network-table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        except CellDoesNotExist:
            return None
        return row_key.value

    def _select_row_by_ip(self, ip: str) -> None:
        table = self.query_one("#network-table", DataTable)
        try:
            row_index = table.get_row_index(ip)
        except RowDoesNotExist:
            return
        table.cursor_coordinate = Coordinate(row=row_index, column=0)

    def _update_detail(self) -> None:
        detail = self.query_one("#network-detail", Static)
        ip = self._selected_ip()
        if ip is None:
            detail.update("[dim]Select a device (↑/↓) to see its open ports.[/]")
            return

        device = next((d for d in self._devices if d.ip == ip), None)
        label = device.hostname or device.vendor if device else None
        header = f"[bold]{ip}[/]" + (f" — {label}" if label else "")
        detail.update(f"{header}\n{_format_ports_detail(self._portscan_results.get(ip))}")
