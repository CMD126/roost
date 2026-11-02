import asyncio
import platform
import shutil
import subprocess

import pytest

from docker.errors import ImageNotFound

from roost.collectors import docker_containers, host, network, opencanary, portscan, uptime
from roost.collectors._arp import get_mac
from roost.collectors._ping import ping
from roost.collectors.opencanary import _parse_event
from roost.config import (
    CanaryConfig,
    DockerConfig,
    HostConfig,
    NetworkConfig,
    PortScanConfig,
    UptimeConfig,
    UptimeTarget,
)


def _icmp_available() -> bool:
    """True if the system ping binary can reach 127.0.0.1 (not the case in
    many containers / restricted CI runners: no binary, or no ICMP perms)."""
    if shutil.which("ping") is None:
        return False
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        return subprocess.run(
            ["ping", count_flag, "1", "127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


requires_icmp = pytest.mark.skipif(not _icmp_available(), reason="ICMP ping to 127.0.0.1 unavailable")


@requires_icmp
async def test_ping_loopback_succeeds():
    latency = await ping("127.0.0.1", timeout=2.0)
    assert latency is not None
    assert latency >= 0


async def test_ping_unroutable_address_times_out():
    # TEST-NET-1, reserved for documentation: guaranteed not to respond.
    latency = await ping("192.0.2.1", timeout=0.5)
    assert latency is None


async def test_host_collect_returns_plausible_metrics():
    metrics = await host.collect(HostConfig(enabled=True))
    assert metrics is not None
    assert 0.0 <= metrics.cpu_percent <= 100.0
    assert 0.0 <= metrics.mem_percent <= 100.0
    assert metrics.mem_total_gb > 0
    assert metrics.uptime_seconds >= 0


async def test_host_collect_disabled_returns_none():
    assert await host.collect(HostConfig(enabled=False)) is None


async def test_host_collect_swallows_psutil_failure_instead_of_crashing(monkeypatch):
    # A restricted/sandboxed host can make psutil raise OSError (denied
    # /proc access, missing disk mount, ...) — this must degrade to None,
    # not propagate through the asyncio.gather() in _refresh_fast() and
    # take Docker/Uptime's results down with it for that cycle.
    def raise_oserror(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(host.psutil, "virtual_memory", raise_oserror)
    assert await host.collect(HostConfig(enabled=True)) is None


async def test_docker_collect_disabled_reports_unavailable():
    snapshot = await docker_containers.collect(DockerConfig(enabled=False))
    assert snapshot.available is False
    assert snapshot.containers == []


async def test_docker_collect_unreachable_ssh_host_reports_unavailable_instead_of_crashing():
    # Port 1 on loopback is closed, so paramiko's own socket.connect() raises
    # a plain OSError before docker-py gets a chance to wrap it as a
    # DockerException — this must be caught, not left to crash the app.
    config = DockerConfig(enabled=True, host="ssh://nobody@127.0.0.1:1")
    snapshot = await docker_containers.collect(config)
    assert snapshot.available is False
    assert snapshot.error


async def test_docker_collect_bad_ssh_banner_reports_unavailable_instead_of_crashing():
    # A real listener that isn't actually SSH (e.g. something else bound to
    # that port, or a middlebox that intercepts the connection) makes
    # paramiko raise its own SSHException — a different hierarchy entirely
    # from OSError/DockerException — while reading the protocol banner.
    # This must degrade gracefully too, exactly like the closed-port case.
    async def handle(reader, writer):
        writer.write(b"Not allowed at this time\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        config = DockerConfig(enabled=True, host=f"ssh://nobody@127.0.0.1:{port}")
        snapshot = await docker_containers.collect(config)

    assert snapshot.available is False
    assert snapshot.error


class _FakeContainer:
    """Enough of docker-py's Container surface to drive _collect_sync: real
    attribute access (name, status), a .image property that raises exactly
    like docker-py's does when the backing image was removed later (e.g.
    `docker image prune`) while the container itself still exists.
    """

    def __init__(self, name: str, status: str) -> None:
        self.name = name
        self.status = status

    @property
    def image(self):
        raise ImageNotFound("no such image: sha256:deadbeef")


class _FakeContainerCollection:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self._containers = containers

    def list(self, all=True):
        return self._containers


class _FakeDockerClient:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self.containers = _FakeContainerCollection(containers)

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


async def test_docker_collect_one_container_with_missing_image_does_not_fail_whole_snapshot(monkeypatch):
    # A dangling image reference on one container must degrade that
    # container's image field, not abort the whole containers.list() loop
    # and report the entire panel unavailable.
    fake_client = _FakeDockerClient([_FakeContainer(name="stale-app", status="exited")])
    monkeypatch.setattr(docker_containers.docker, "from_env", lambda: fake_client)

    snapshot = await docker_containers.collect(DockerConfig(enabled=True))

    assert snapshot.available is True
    assert len(snapshot.containers) == 1
    assert snapshot.containers[0].name == "stale-app"
    assert snapshot.containers[0].image == "unknown"


async def test_uptime_collect_tcp_closed_port_is_down():
    targets = [UptimeTarget(name="closed", type="tcp", address="127.0.0.1", port=1)]
    results = await uptime.collect(UptimeConfig(enabled=True, timeout=1.0, targets=targets))
    assert len(results) == 1
    assert results[0].up is False


async def test_uptime_collect_empty_targets_returns_empty_list():
    assert await uptime.collect(UptimeConfig(enabled=True, targets=[])) == []


async def test_uptime_collect_http_bad_url_reports_down_instead_of_crashing():
    # httpx.InvalidURL (e.g. from a typo'd port) subclasses Exception
    # directly, not httpx.HTTPError — a config typo on one target must mark
    # that target down, not crash the whole app via collect()'s gather().
    target = UptimeTarget(name="bad-port", type="http", url="http://127.0.0.1:notaport")
    results = await uptime.collect(UptimeConfig(enabled=True, timeout=1.0, targets=[target]))
    assert len(results) == 1
    assert results[0].up is False
    assert results[0].detail == "InvalidURL"


@requires_icmp
async def test_network_collect_loopback_range_finds_self():
    devices = await network.collect(NetworkConfig(enabled=True, cidr="127.0.0.0/30", timeout=1.0))
    assert any(d.ip == "127.0.0.1" for d in devices)


async def test_network_collect_no_cidr_returns_empty_list():
    assert await network.collect(NetworkConfig(enabled=True, cidr="")) == []


@requires_icmp
async def test_network_collect_enriches_loopback_with_mac_or_none():
    # No assertion on the value itself (loopback has no ARP entry, a real LAN
    # host would), just that enrichment never raises and the field exists.
    devices = await network.collect(NetworkConfig(enabled=True, cidr="127.0.0.0/30", timeout=1.0))
    self_device = next(d for d in devices if d.ip == "127.0.0.1")
    assert self_device.mac is None or isinstance(self_device.mac, str)


async def test_vendor_lookup_known_oui():
    vendor = await network._vendor_for("b8:27:eb:00:00:00")
    assert vendor == "Raspberry Pi Foundation"


async def test_vendor_lookup_none_mac_returns_none():
    assert await network._vendor_for(None) is None


async def test_vendor_lookup_swallows_any_lookup_failure_not_just_not_found(monkeypatch):
    # On first run or a stale cache, mac_vendor_lookup transparently tries
    # to fetch a fresh vendor list over the network — which can fail with
    # connection errors unrelated to VendorNotFoundError on a LAN with no
    # outbound internet. Vendor is optional enrichment either way: any
    # failure here must degrade to None, not crash the whole app.
    async def raise_connection_error(mac):
        raise OSError("network unreachable")

    monkeypatch.setattr(network._mac_lookup, "lookup", raise_connection_error)
    assert await network._vendor_for("aa:bb:cc:dd:ee:ff") is None


async def test_get_mac_never_raises_for_address_with_no_arp_entry():
    mac = await get_mac("203.0.113.1")  # TEST-NET-3: never pinged, no ARP entry
    assert mac is None


async def test_portscan_risky_ports_classification():
    assert 23 in portscan.RISKY_PORTS  # telnet
    assert 3389 in portscan.RISKY_PORTS  # rdp
    assert 22 not in portscan.RISKY_PORTS  # ssh


async def test_portscan_finds_open_port_and_reads_banner():
    async def handle(reader, writer):
        writer.write(b"TEST-BANNER-1.0\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        config = PortScanConfig(enabled=True, timeout=1.0, concurrency=8, ports=[port])
        results = await portscan.scan_hosts(["127.0.0.1"], config)

    open_ports = results["127.0.0.1"].open_ports
    assert len(open_ports) == 1
    assert open_ports[0].port == port
    assert open_ports[0].banner == "TEST-BANNER-1.0"
    assert open_ports[0].risky is False


async def test_portscan_closed_port_not_reported_open():
    config = PortScanConfig(enabled=True, timeout=0.5, concurrency=8, ports=[1])
    results = await portscan.scan_hosts(["127.0.0.1"], config)
    assert results["127.0.0.1"].open_ports == []


async def test_portscan_disabled_returns_empty_dict():
    config = PortScanConfig(enabled=False, ports=[1])
    assert await portscan.scan_hosts(["127.0.0.1"], config) == {}


# Shaped after real lines captured from an actual OpenCanary deployment
# (host/username anonymized; structure and every other field left untouched) —
# both flavors: an internal housekeeping message and a real login attempt.
_CANARY_STARTUP_LINE = (
    '{"dst_host": "", "dst_port": -1, "local_time": "2026-07-01 21:04:56.021321", '
    '"logdata": {"msg": {"logdata": "Canary running!!!"}}, "logtype": 1001, '
    '"node_id": "homelab-canary", "src_host": "", "src_port": -1, '
    '"utc_time": "2026-07-01 21:04:56.022203"}'
)
_CANARY_FTP_LOGIN_LINE = (
    '{"dst_host": "192.168.1.10", "dst_port": 21, "local_time": "2026-06-29 20:53:04.888789", '
    '"logdata": {"PASSWORD": "ola", "USERNAME": "ola"}, "logtype": 2000, '
    '"node_id": "opencanary-1", "src_host": "192.168.1.50", "src_port": 50956, '
    '"utc_time": "2026-06-29 20:53:04.889015"}'
)


def test_parse_event_skips_housekeeping_lines():
    assert _parse_event(_CANARY_STARTUP_LINE) is None


def test_parse_event_skips_invalid_json():
    assert _parse_event("not json") is None


def test_parse_event_extracts_real_login_attempt_as_high_severity():
    event = _parse_event(_CANARY_FTP_LOGIN_LINE)

    assert event is not None
    assert event.source == "canary"
    assert event.event_type == "credential_attempt"
    assert event.severity == "high"
    assert event.target == "192.168.1.50"
    assert event.service == "ftp"
    assert event.summary == "login attempt: ola/ola"
    assert event.ts == "2026-06-29 20:53:04.889015"
    assert event.detail["dst_port"] == 21


def test_parse_event_formats_http_path_as_medium_severity():
    line = (
        '{"dst_host": "192.168.1.10", "dst_port": 80, '
        '"logdata": {"PATH": "/admin/login.php"}, "logtype": 3000, '
        '"src_host": "203.0.113.7", "utc_time": "2026-07-01 10:00:00"}'
    )
    event = _parse_event(line)

    assert event is not None
    assert event.event_type == "http_probe"
    assert event.severity == "medium"
    assert event.service == "http"
    assert event.summary == "GET /admin/login.php"


def test_parse_event_bare_connection_is_low_severity():
    line = (
        '{"dst_host": "192.168.1.10", "dst_port": 22, "logdata": {}, '
        '"logtype": 4000, "src_host": "203.0.113.7", "utc_time": "2026-07-01 10:00:00"}'
    )
    event = _parse_event(line)

    assert event is not None
    assert event.event_type == "connection"
    assert event.severity == "low"
    assert event.summary == "connection"


async def test_opencanary_collect_disabled_returns_empty_list():
    assert await opencanary.collect(CanaryConfig(enabled=False, ssh_target="host")) == []


async def test_opencanary_collect_no_ssh_target_returns_empty_list():
    assert await opencanary.collect(CanaryConfig(enabled=True, ssh_target="")) == []
