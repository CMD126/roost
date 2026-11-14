# Security policy

Roost is a monitoring tool that ingests data from untrusted sources (honeypot
logs, service banners, reverse DNS) and actively probes the network it is
pointed at, so security bugs in it matter. Thanks for taking the time to report
one.

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release
branches.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: on the repository page, go to
**Security > Report a vulnerability**. Include what you found, how to reproduce
it (a config snippet, a log line or a banner is ideal), and what impact you
think it has.

I aim to acknowledge reports within a week. Fixes land on `main` together with
a regression test, and I'm happy to credit you in the fix if you'd like.

## What counts

In scope, for example:

- Input from the network or a honeypot log that crashes the dashboard, injects
  markup or terminal escape sequences, or is otherwise interpreted instead of
  displayed.
- Command or argument injection through anything Roost passes to `ssh`, `ping`,
  `ip`/`arp` or a remote shell.
- Ways to make Roost scan outside the configured range, or bypass the
  private-range and size checks on `network.cidr` without
  `network.allow_public: true`.
- Leaking secrets or internal network details into places they shouldn't go
  (logs, the events database of another user, the repository).

Out of scope:

- The fact that the exposure scan can be noticed or blocked by an IDS; it is a
  plain TCP connect scan by design.
- Findings that require an attacker who can already edit your `config.yaml` or
  run commands as your user.
- Vulnerabilities in OpenCanary, Docker or other third-party software Roost
  talks to (please report those upstream).

## Using Roost responsibly

Roost sends network probes (ping sweep, TCP connects, banner reads). Only point
it at networks you own or are explicitly authorized to test.
