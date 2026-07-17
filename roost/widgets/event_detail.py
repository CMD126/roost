from __future__ import annotations

import json

from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Static

from ..models import SecurityEvent

_SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "dim"}


class Acknowledge(Message):
    """Bubbles up to the App, which owns the SocStore and re-renders the
    security panel once the status is persisted.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__()


class EventDetailScreen(ModalScreen[None]):
    """Full detail for one SecurityEvent — everything the compact table row
    couldn't show, including the raw structured data behind the summary.
    """

    # ModalScreen does not bind Escape by default.
    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("a", "acknowledge_and_close", "Ack"),
    ]

    DEFAULT_CSS = """
    EventDetailScreen {
        align: center middle;
    }

    #event-detail-box {
        width: 70%;
        max-width: 100;
        height: auto;
        max-height: 80%;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, event: SecurityEvent) -> None:
        super().__init__()
        self._event = event

    def compose(self):
        event = self._event
        color = _SEVERITY_COLOR.get(event.severity, "")
        sev_label = f"[{color}]{event.severity.upper()}[/]" if color else event.severity.upper()
        detail_text = json.dumps(event.detail, indent=2)

        body = (
            f"[bold]{event.summary}[/]\n\n"
            f"Time (UTC):  {event.ts}\n"
            f"Source:      {event.source}\n"
            f"Type:        {event.event_type}\n"
            f"Severity:    {sev_label}\n"
            f"Target:      {event.target}\n"
            f"Service:     {event.service or '—'}\n"
            f"Status:      {event.status}\n\n"
            f"[dim]Raw detail:[/]\n{detail_text}\n\n"
            f"[dim][a] acknowledge   [esc] close[/]"
        )
        box = Vertical(Static(body), id="event-detail-box")
        box.can_focus = True
        yield box

    def on_mount(self) -> None:
        # Without an explicit focus target, a modal opened via mouse click
        # can leave the screen with no focused widget, which has been
        # observed to swallow the very next key press instead of acting on
        # it (e.g. Escape not closing on the first try).
        self.query_one("#event-detail-box").focus()

    def action_acknowledge_and_close(self) -> None:
        self.post_message(Acknowledge(self._event.key))
        self.dismiss()
