from roost.models import NetworkDevice, OpenPort, SecurityEvent
from roost.soc import SocStore, device_key


def _store(tmp_path) -> SocStore:
    return SocStore(tmp_path / "events.db")


def _event(key_suffix: str = "1") -> SecurityEvent:
    return SecurityEvent(
        ts="2026-07-01 10:00:00.000000",
        source="canary",
        event_type="credential_attempt",
        severity="high",
        target="203.0.113.7",
        service="ftp",
        summary=f"login attempt {key_suffix}",
        detail={"USERNAME": "admin"},
    )


def test_record_events_dedups_by_key(tmp_path):
    store = _store(tmp_path)
    event = _event()

    assert store.record_events([event]) == [event]
    assert store.record_events([event]) == []  # already persisted, skipped
    assert len(store.recent_events()) == 1


def test_record_device_snapshot_emits_new_device_once(tmp_path):
    store = _store(tmp_path)
    device = NetworkDevice(ip="192.168.1.50", hostname="laptop", latency_ms=1.0, mac="aa:bb:cc:dd:ee:ff")

    first = store.record_device_snapshot([device])
    assert len(first) == 1
    assert first[0].event_type == "new_device"
    assert first[0].target == "192.168.1.50"

    second = store.record_device_snapshot([device])
    assert second == []  # same device seen again, not new


def test_record_device_snapshot_emits_device_returned_after_absence(tmp_path):
    store = _store(tmp_path)
    device = NetworkDevice(ip="192.168.1.50", hostname="laptop", latency_ms=1.0, mac="aa:bb:cc:dd:ee:ff")

    store.record_device_snapshot([device])  # first sighting -> new_device
    store.record_device_snapshot([])  # device drops off the LAN -> no event
    returned = store.record_device_snapshot([device])  # device is back

    assert len(returned) == 1
    assert returned[0].event_type == "device_returned"


def test_record_port_snapshot_open_close_reopen(tmp_path):
    store = _store(tmp_path)
    key = "192.168.1.50"
    port = OpenPort(port=22, service="ssh", banner=None, risky=False)

    opened = store.record_port_snapshot(key, [port])
    assert len(opened) == 1
    assert opened[0].event_type == "new_port"

    unchanged = store.record_port_snapshot(key, [port])
    assert unchanged == []  # still open, no re-alert

    closed = store.record_port_snapshot(key, [])
    assert closed == []  # closing a port never alerts

    reopened = store.record_port_snapshot(key, [port])
    assert len(reopened) == 1
    assert reopened[0].event_type == "new_port"


def test_record_port_snapshot_risky_port_is_high_severity(tmp_path):
    store = _store(tmp_path)
    risky_port = OpenPort(port=3389, service="rdp", banner=None, risky=True)

    events = store.record_port_snapshot("192.168.1.50", [risky_port])
    assert events[0].severity == "high"


def test_set_status_persists_and_updates_stats(tmp_path):
    store = _store(tmp_path)
    event = _event()
    store.record_events([event])

    assert store.stats().unacknowledged == 1

    store.set_status(event.key, "acknowledged")

    assert store.stats().unacknowledged == 0
    assert store.recent_events()[0].status == "acknowledged"


def test_stats_top_sources_and_services(tmp_path):
    store = _store(tmp_path)
    store.record_events([_event("a"), _event("b")])
    store.record_events([SecurityEvent(
        ts="2026-07-01 11:00:00.000000", source="canary", event_type="http_probe",
        severity="medium", target="203.0.113.9", service="http", summary="GET /",
        detail={},
    )])

    stats = store.stats()
    assert stats.total == 3
    assert stats.top_sources[0] == ("203.0.113.7", 2)
    assert ("ftp", 2) in stats.top_services


def test_recent_events_is_a_triage_queue_not_just_a_log(tmp_path):
    store = _store(tmp_path)
    old_high = SecurityEvent(
        ts="2026-07-01 08:00:00.000000", source="canary", event_type="credential_attempt",
        severity="high", target="203.0.113.7", service="ftp", summary="old high", detail={},
    )
    new_low = SecurityEvent(
        ts="2026-07-01 12:00:00.000000", source="network", event_type="new_device",
        severity="low", target="192.168.1.5", service="", summary="new low", detail={},
    )
    new_medium = SecurityEvent(
        ts="2026-07-01 11:00:00.000000", source="network", event_type="new_port",
        severity="medium", target="192.168.1.6", service="http", summary="new medium", detail={},
    )
    store.record_events([old_high, new_low, new_medium])
    store.set_status(old_high.key, "acknowledged")

    ordered = store.recent_events()

    # Acknowledged sinks to the bottom regardless of recency — there's
    # nothing left to triage about it.
    assert ordered[-1].key == old_high.key
    # Among the unacknowledged, most recent leads — chronological, not
    # weighted by severity (new_low is more recent than new_medium despite
    # being lower severity).
    assert ordered[0].key == new_low.key
    assert ordered[1].key == new_medium.key


def test_stats_open_severity_counts_and_last_event_ts(tmp_path):
    store = _store(tmp_path)
    high = _event("high")
    medium = SecurityEvent(
        ts="2026-07-01 09:00:00.000000", source="canary", event_type="http_probe",
        severity="medium", target="203.0.113.9", service="http", summary="probe", detail={},
    )
    store.record_events([high, medium])

    stats = store.stats()
    assert stats.open_high == 1
    assert stats.open_medium == 1
    assert stats.open_low == 0
    assert stats.last_event_ts == high.ts  # high.ts is later than medium.ts

    store.set_status(high.key, "acknowledged")
    assert store.stats().open_high == 0


def test_device_key_prefers_mac_over_ip():
    device = NetworkDevice(ip="192.168.1.5", hostname=None, latency_ms=None, mac="aa:bb:cc:dd:ee:ff")
    assert device_key(device) == "aa:bb:cc:dd:ee:ff"

    device_no_mac = NetworkDevice(ip="192.168.1.5", hostname=None, latency_ms=None, mac=None)
    assert device_key(device_no_mac) == "192.168.1.5"
