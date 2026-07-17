"""Persistent store for the unified security event log.

SQLite via the stdlib, called synchronously from the app's refresh
coroutines. Roost has no real thread parallelism — `run_worker` groups are
cooperatively scheduled on one asyncio event loop thread — so a single
connection needs no locking beyond what sqlite3 already does.

Besides the event log itself, this owns the device/port "presence" tables
used for network change detection. That state is persisted (not kept as an
in-memory "previous scan") specifically so a restart doesn't make every
already-known device/port look newly discovered again.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import NetworkDevice, OpenPort, SecurityEvent, SocStats

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    key TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    service TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
);

CREATE TABLE IF NOT EXISTS known_devices (
    key TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    mac TEXT,
    present INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS known_ports (
    device_key TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_changed TEXT NOT NULL,
    PRIMARY KEY (device_key, port)
);
"""


def device_key(device: NetworkDevice) -> str:
    """Identity used for presence tracking — MAC when we have it (survives a
    DHCP lease change), falling back to IP otherwise.
    """
    return device.mac or device.ip


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
    return SecurityEvent(
        ts=row["ts"],
        source=row["source"],
        event_type=row["event_type"],
        severity=row["severity"],
        target=row["target"],
        service=row["service"],
        summary=row["summary"],
        detail=json.loads(row["detail_json"]),
        status=row["status"],
    )


class SocStore:
    """Owns events.db: event history + triage state, and the device/port
    presence tables used to detect network changes.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def record_events(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Persists events, skipping ones already seen (by key). Returns only
        the ones that were newly inserted.
        """
        new_events = []
        for event in events:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO events "
                "(key, ts, source, event_type, severity, target, service, summary, detail_json, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.key, event.ts, event.source, event.event_type, event.severity,
                    event.target, event.service, event.summary,
                    json.dumps(event.detail), event.status,
                ),
            )
            if cur.rowcount:
                new_events.append(event)
        self._conn.commit()
        return new_events

    def record_device_snapshot(self, devices: list[NetworkDevice]) -> list[SecurityEvent]:
        """Diffs the current device list against persisted presence state.
        Emits `new_device` the first time a device is ever seen, and
        `device_returned` when a known device reappears after being marked
        absent. Disappearance itself never emits — it only flips the flag so
        a later reappearance can be detected.
        """
        now = _now()
        new_events: list[SecurityEvent] = []
        seen_keys = set()

        for device in devices:
            key = device_key(device)
            seen_keys.add(key)
            label = device.hostname or device.vendor or device.ip
            detail = {"ip": device.ip, "mac": device.mac, "hostname": device.hostname, "vendor": device.vendor}
            row = self._conn.execute("SELECT present FROM known_devices WHERE key = ?", (key,)).fetchone()

            if row is None:
                self._conn.execute(
                    "INSERT INTO known_devices (key, ip, mac, present, first_seen, last_seen) "
                    "VALUES (?, ?, ?, 1, ?, ?)",
                    (key, device.ip, device.mac, now, now),
                )
                new_events.append(SecurityEvent(
                    ts=now, source="network", event_type="new_device", severity="medium",
                    target=device.ip, service="", summary=f"new device on LAN: {label}", detail=detail,
                ))
            elif row["present"] == 0:
                self._conn.execute(
                    "UPDATE known_devices SET present = 1, last_seen = ?, ip = ? WHERE key = ?",
                    (now, device.ip, key),
                )
                new_events.append(SecurityEvent(
                    ts=now, source="network", event_type="device_returned", severity="medium",
                    target=device.ip, service="", summary=f"device returned to LAN: {label}", detail=detail,
                ))
            else:
                self._conn.execute("UPDATE known_devices SET last_seen = ?, ip = ? WHERE key = ?", (now, device.ip, key))

        if seen_keys:
            placeholders = ",".join("?" * len(seen_keys))
            self._conn.execute(
                f"UPDATE known_devices SET present = 0 WHERE present = 1 AND key NOT IN ({placeholders})",
                tuple(seen_keys),
            )
        else:
            self._conn.execute("UPDATE known_devices SET present = 0 WHERE present = 1")

        return self.record_events(new_events)

    def record_port_snapshot(self, target_key: str, open_ports: list[OpenPort]) -> list[SecurityEvent]:
        """Same presence-flip pattern as devices, scoped to one device's open
        ports. Only a closed->open transition ever alerts — closing a port is
        never itself an event.
        """
        now = _now()
        new_events: list[SecurityEvent] = []
        open_port_numbers = {p.port for p in open_ports}

        for port in open_ports:
            row = self._conn.execute(
                "SELECT state FROM known_ports WHERE device_key = ? AND port = ?", (target_key, port.port)
            ).fetchone()

            if row is None:
                self._conn.execute(
                    "INSERT INTO known_ports (device_key, port, state, first_seen, last_changed) "
                    "VALUES (?, ?, 'open', ?, ?)",
                    (target_key, port.port, now, now),
                )
                new_events.append(self._new_port_event(now, target_key, port))
            elif row["state"] == "closed":
                self._conn.execute(
                    "UPDATE known_ports SET state = 'open', last_changed = ? WHERE device_key = ? AND port = ?",
                    (now, target_key, port.port),
                )
                new_events.append(self._new_port_event(now, target_key, port))

        open_rows = self._conn.execute(
            "SELECT port FROM known_ports WHERE device_key = ? AND state = 'open'", (target_key,)
        ).fetchall()
        for row in open_rows:
            if row["port"] not in open_port_numbers:
                self._conn.execute(
                    "UPDATE known_ports SET state = 'closed', last_changed = ? WHERE device_key = ? AND port = ?",
                    (now, target_key, row["port"]),
                )

        return self.record_events(new_events)

    @staticmethod
    def _new_port_event(now: str, target_key: str, port: OpenPort) -> SecurityEvent:
        severity = "high" if port.risky else "medium"
        banner = f" ({port.banner})" if port.banner else ""
        return SecurityEvent(
            ts=now, source="network", event_type="new_port", severity=severity,
            target=target_key, service=port.service,
            summary=f"port {port.port}/{port.service} opened{banner}",
            detail={"port": port.port, "service": port.service, "banner": port.banner, "risky": port.risky},
        )

    def recent_events(self, limit: int = 200) -> list[SecurityEvent]:
        """A triage queue, not just a log: unacknowledged first (there's
        nothing to do about an acknowledged one), most recent first within
        that — chronological, not weighted by severity.
        """
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY "
            "(status = 'acknowledged'), "
            "ts DESC "
            "LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_event(row) for row in rows]

    def set_status(self, key: str, status: str) -> None:
        self._conn.execute("UPDATE events SET status = ? WHERE key = ?", (status, key))
        self._conn.commit()

    def stats(self) -> SocStats:
        total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        unacknowledged = self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE status != 'acknowledged'"
        ).fetchone()[0]

        cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S.%f")
        cutoff_7d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S.%f")
        count_24h = self._conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff_24h,)).fetchone()[0]
        count_7d = self._conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff_7d,)).fetchone()[0]

        open_counts = dict(self._conn.execute(
            "SELECT severity, COUNT(*) FROM events WHERE status != 'acknowledged' GROUP BY severity"
        ).fetchall())

        last_event = self._conn.execute("SELECT ts FROM events ORDER BY ts DESC LIMIT 1").fetchone()

        top_sources = self._conn.execute(
            "SELECT target, COUNT(*) as n FROM events WHERE target != '' GROUP BY target ORDER BY n DESC LIMIT 5"
        ).fetchall()
        top_services = self._conn.execute(
            "SELECT service, COUNT(*) as n FROM events WHERE service != '' GROUP BY service ORDER BY n DESC LIMIT 5"
        ).fetchall()

        return SocStats(
            total=total,
            unacknowledged=unacknowledged,
            count_24h=count_24h,
            count_7d=count_7d,
            open_high=open_counts.get("high", 0),
            open_medium=open_counts.get("medium", 0),
            open_low=open_counts.get("low", 0),
            last_event_ts=last_event["ts"] if last_event else None,
            top_sources=[(row["target"], row["n"]) for row in top_sources],
            top_services=[(row["service"], row["n"]) for row in top_services],
        )
