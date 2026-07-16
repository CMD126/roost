import asyncio

from roost.collectors import docker_containers, host, network, opencanary, portscan, uptime
from roost.collectors._arp import get_mac
from roost.collectors._ping import ping
from roost.collectors.opencanary import _parse_alert
from roost.config import (
    CanaryConfig,
    DockerConfig,
    HostConfig,
    NetworkConfig,
    PortScanConfig,
    UptimeConfig,
    UptimeTarget,
)


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


async def test_docker_collect_disabled_reports_unavailable():
    snapshot = await docker_containers.collect(DockerConfig(enabled=False))
    assert snapshot.available is False
    assert snapshot.containers == []


async def test_uptime_collect_tcp_closed_port_is_down():
    targets = [UptimeTarget(name="closed", type="tcp", address="127.0.0.1", port=1)]
    results = await uptime.collect(UptimeConfig(enabled=True, timeout=1.0, targets=targets))
    assert len(results) == 1
    assert results[0].up is False


async def test_uptime_collect_empty_targets_returns_empty_list():
    assert await uptime.collect(UptimeConfig(enabled=True, targets=[])) == []


async def test_network_collect_loopback_range_finds_self():
    devices = await network.collect(NetworkConfig(enabled=True, cidr="127.0.0.0/30", timeout=1.0))
    assert any(d.ip == "127.0.0.1" for d in devices)


async def test_network_collect_no_cidr_returns_empty_list():
    assert await network.collect(NetworkConfig(enabled=True, cidr="")) == []


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


def test_parse_alert_skips_housekeeping_lines():
    assert _parse_alert(_CANARY_STARTUP_LINE) is None


def test_parse_alert_skips_invalid_json():
    assert _parse_alert("not json") is None


def test_parse_alert_extracts_real_login_attempt():
    alert = _parse_alert(_CANARY_FTP_LOGIN_LINE)

    assert alert is not None
    assert alert.src_host == "192.168.1.50"
    assert alert.dst_port == 21
    assert alert.service == "ftp"
    assert alert.summary == "login attempt: ola/ola"
    assert alert.utc_time == "2026-06-29 20:53:04.889015"


def test_parse_alert_formats_http_path():
    line = (
        '{"dst_host": "192.168.1.10", "dst_port": 80, '
        '"logdata": {"PATH": "/admin/login.php"}, "logtype": 3000, '
        '"src_host": "203.0.113.7", "utc_time": "2026-07-01 10:00:00"}'
    )
    alert = _parse_alert(line)

    assert alert is not None
    assert alert.service == "http"
    assert alert.summary == "GET /admin/login.php"


async def test_opencanary_collect_disabled_returns_empty_list():
    assert await opencanary.collect(CanaryConfig(enabled=False, ssh_target="host")) == []


async def test_opencanary_collect_no_ssh_target_returns_empty_list():
    assert await opencanary.collect(CanaryConfig(enabled=True, ssh_target="")) == []
