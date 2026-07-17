"""Textual's DataTable only fires RowSelected on a *second* click on a row
that's already under the cursor (the first click just moves the cursor
there, same as an arrow key) — a real dashboard opens on the first click.

Note this can't be done by overriding _on_click and simply not calling
super(): Textual's message dispatch (MessagePump._get_dispatch_methods)
walks every class in the MRO and invokes each one's own same-named handler,
not just the most-derived override — so DataTable's own _on_click always
runs too, regardless of what a subclass's _on_click does or whether it calls
event.stop(). The earlier version of this class posted its own RowSelected
message from the override, which meant a single click fired RowSelected
*twice* (once from here, once from DataTable's own handler seeing the cursor
already on the clicked cell) — every click opened two stacked modals.
"""

from __future__ import annotations

from textual import events
from textual.coordinate import Coordinate
from textual.widgets import DataTable


class ClickToSelectDataTable(DataTable):
    """A DataTable where a single click on a row selects it immediately."""

    def _on_click(self, event: events.Click) -> None:
        meta = event.style.meta
        row_index = meta.get("row")
        column_index = meta.get("column")
        clicked_a_row = (
            row_index is not None
            and column_index is not None
            and row_index != -1
            and self.show_cursor
            and self.cursor_type != "none"
        )
        if not clicked_a_row:
            return

        # Pre-position the cursor to the clicked cell *before* DataTable's
        # own _on_click runs (it always will, right after this — see module
        # docstring). It compares the click's coordinate against the current
        # cursor to decide whether to fire RowSelected; matching it here
        # makes that comparison true on the very first click, so DataTable
        # posts RowSelected itself using its own message/scroll-into-view
        # logic — no duplicate message needed from this override.
        self.cursor_coordinate = Coordinate(row_index, column_index)
