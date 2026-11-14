# Changelog

## 0.1.0 (unreleased)

Initial release candidate for homelab use:

- Terminal tabs for security events, LAN devices and exposed ports, Docker containers, host metrics and service uptime.
- OpenCanary log ingestion over SSH and SQLite-backed event history, triage and network change detection.
- Private-range scan guardrails and plain-text handling of untrusted network data.
- `roost --demo` with invented data, no scanning and temporary event storage.

Known limitations:

- Exposure and severity heuristics do not establish that a service is vulnerable; CVE correlation is not implemented.
- OpenCanary and remote host monitoring require separately configured SSH access; Roost does not deploy a honeypot.
- Automated platform coverage is Ubuntu with Python 3.10–3.13. Other operating systems are not release-qualified by that CI matrix.

Builds are checked as source and wheel distributions, and the wheel is installed in a clean environment for a CLI and version smoke check. These checks do not establish production readiness or replace testing against your own lab.
