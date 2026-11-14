"""Helpers for text that comes from the network rather than from us."""

from __future__ import annotations


def printable(text: str, limit: int | None = None) -> str:
    """Drops control characters (ESC, CR, BEL, ...) from untrusted text.

    Service banners and honeypot log fields are chosen by whoever is on the
    other end of the connection. Left as-is, an ESC byte in a banner would be
    passed through to the user's terminal, where escape sequences can move
    the cursor, rewrite the title bar or hide output.
    """
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text).strip()
    return cleaned[:limit] if limit is not None else cleaned
