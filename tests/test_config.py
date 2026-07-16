from pathlib import Path

from roost.config import load_config


def test_load_config_missing_file_returns_defaults(tmp_path: Path):
    config = load_config(tmp_path / "does-not-exist.yaml")

    assert config.refresh_interval == 5.0
    assert config.docker.enabled is True
    assert config.uptime.targets == []


def test_load_config_parses_uptime_targets(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
refresh_interval: 10
docker:
  enabled: false
uptime:
  timeout: 2.5
  targets:
    - name: Router
      type: tcp
      address: 192.168.1.1
      port: 80
    - name: Site
      type: http
      url: https://example.com
network:
  cidr: 10.0.0.0/24
  scan_interval: 30
""",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.refresh_interval == 10
    assert config.docker.enabled is False
    assert config.uptime.timeout == 2.5
    assert len(config.uptime.targets) == 2
    assert config.uptime.targets[0].name == "Router"
    assert config.uptime.targets[0].port == 80
    assert config.uptime.targets[1].url == "https://example.com"
    assert config.network.cidr == "10.0.0.0/24"
    assert config.network.scan_interval == 30


def test_load_config_parses_remote_host(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
host:
  remote:
    ssh_target: "user@192.168.1.10"
    python: "/opt/venv/bin/python3"
""",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.host.remote is not None
    assert config.host.remote.ssh_target == "user@192.168.1.10"
    assert config.host.remote.python == "/opt/venv/bin/python3"


def test_load_config_host_remote_defaults_to_none(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("host:\n  enabled: true\n", encoding="utf-8")

    config = load_config(config_file)

    assert config.host.remote is None


def test_load_config_parses_portscan_overrides(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
network:
  cidr: 10.0.0.0/24
  portscan:
    enabled: false
    interval: 120
    timeout: 2.0
    concurrency: 16
    ports: [22, 80, 443]
""",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.network.portscan.enabled is False
    assert config.network.portscan.interval == 120
    assert config.network.portscan.timeout == 2.0
    assert config.network.portscan.concurrency == 16
    assert config.network.portscan.ports == [22, 80, 443]


def test_load_config_portscan_defaults(tmp_path: Path):
    config = load_config(tmp_path / "does-not-exist.yaml")

    assert config.network.portscan.enabled is True
    assert 22 in config.network.portscan.ports
    assert 23 in config.network.portscan.ports


def test_load_config_canary_defaults_to_disabled(tmp_path: Path):
    config = load_config(tmp_path / "does-not-exist.yaml")

    assert config.canary.enabled is False
    assert config.canary.log_path == "/var/tmp/opencanary.log"


def test_load_config_parses_canary_overrides(tmp_path: Path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
canary:
  enabled: true
  ssh_target: "user@192.168.1.10"
  log_path: "/custom/path.log"
  tail_lines: 50
  interval: 15
""",
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.canary.enabled is True
    assert config.canary.ssh_target == "user@192.168.1.10"
    assert config.canary.log_path == "/custom/path.log"
    assert config.canary.tail_lines == 50
    assert config.canary.interval == 15
