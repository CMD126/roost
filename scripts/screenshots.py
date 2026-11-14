"""Regenerates the README screenshots from demo mode.

    python scripts/screenshots.py

Runs DemoDashboard headless (Textual's run_test), so it needs no terminal,
no network and no config, and writes SVGs into docs/.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from roost.demo import DemoDashboard

DOCS = Path(__file__).resolve().parent.parent / "docs"
SIZE = (132, 36)


async def main() -> None:
    DOCS.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="roost-shots-") as tmp:
        app = DemoDashboard(Path(tmp))
        async with app.run_test(size=SIZE) as pilot:
            await app._refresh_network()
            await app._refresh_portscan()
            await app._refresh_canary()
            await app._refresh_fast()
            await pilot.pause(0.5)
            # Park the cursor on the newest honeypot login attempt, then open it.
            events = app.soc.recent_events()
            row = next(i for i, e in enumerate(events) if e.event_type == "credential_attempt")
            app.query_one("#security-table").move_cursor(row=row)
            await pilot.pause(0.2)
            app.save_screenshot("screenshot.svg", path=str(DOCS))

            await pilot.press("enter")
            await pilot.pause(0.3)
            app.save_screenshot("event-detail.svg", path=str(DOCS))
            await pilot.press("escape")

            await pilot.press("2")
            await pilot.pause(0.2)
            table = app.query_one("#network-table")
            table.move_cursor(row=len(app._last_devices) - 1)
            await pilot.pause(0.3)
            app.save_screenshot("network.svg", path=str(DOCS))
        app.soc.close()
    print(f"wrote screenshots to {DOCS}")


if __name__ == "__main__":
    asyncio.run(main())
