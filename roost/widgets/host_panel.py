from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Label, ProgressBar, Static

from ..models import HostMetrics


def _format_uptime(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


class _Meter(Horizontal):
    def __init__(self, label: str, meter_id: str) -> None:
        super().__init__(classes="meter-row")
        self._label = label
        self._meter_id = meter_id

    def compose(self):
        yield Label(self._label, classes="meter-label")
        yield ProgressBar(total=100, id=self._meter_id, show_eta=False)


class HostPanel(Vertical):
    """CPU, memory, disk and uptime — of a target set in config.host, local by default."""

    def __init__(self, *args, source_label: str = "local", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._source_label = source_label

    def compose(self):
        yield Static(f"HOST — {self._source_label}", classes="panel-title")
        yield _Meter("CPU", "cpu-bar")
        yield _Meter("Memory", "mem-bar")
        yield _Meter("Disk", "disk-bar")
        yield Static("", id="host-details", classes="panel-summary")

    def update_data(self, metrics: HostMetrics | None) -> None:
        if metrics is None:
            self.query_one("#host-details", Static).update("[red]Host metrics disabled[/]")
            return

        self.query_one("#cpu-bar", ProgressBar).update(progress=metrics.cpu_percent)
        self.query_one("#mem-bar", ProgressBar).update(progress=metrics.mem_percent)
        self.query_one("#disk-bar", ProgressBar).update(progress=metrics.disk_percent)

        temp = f"{metrics.temperature_c:.0f}°C" if metrics.temperature_c is not None else "n/a"
        details = (
            f"RAM {metrics.mem_used_gb:.1f}/{metrics.mem_total_gb:.1f} GB   "
            f"Disk {metrics.disk_used_gb:.0f}/{metrics.disk_total_gb:.0f} GB\n"
            f"Uptime {_format_uptime(metrics.uptime_seconds)}   Temp {temp}"
        )
        self.query_one("#host-details", Static).update(details)
