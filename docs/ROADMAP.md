# Roadmap

Status: **complete through v0.3.0** (2026-09-28).

The original 10-item roadmap (tests, profiles, structured output, results
store, fleet execution, keyring vault, alerting sinks, daemon mode,
CHANGELOG, CI) shipped in PR #1 and was hardened in the v0.3.0 polish pass
(build-backend fix, coverage ≥70%, ruff, README sync, version consistency).

## Current state

`jms-porthole` is a single-package Click CLI wrapping paramiko SSH sessions,
with:

- 30+ subcommands (monitor, broadcast, scan, probe, spray, health, alert,
  daemon, profiles, …)
- pytest suite (~935 tests) and GitHub Actions CI (lint + coverage + wheel
  smoke) on Python 3.9/3.11/3.12
- OS keyring-backed credentials, YAML host-group profiles, SQLite run history,
  and pluggable alert sinks (webhook / Slack / email)

## Explicitly out of scope (by decision)

- `asyncssh` rewrite (thread-pool `concurrent.futures` is sufficient)
- HashiCorp Vault / `pass` backends (OS keyring is sufficient)
- JSONL results store (SQLite is sufficient)

## Possible later work

- Raise coverage on remaining 0%-modules (`backup`, `broadcast`, `keydeploy`,
  `logsearch`, `screenshot`, `shell`, `transfer`) and flesh out `netmap` /
  `spray` paths
- Publish to PyPI (`pipx install jms-porthole`) via the tag-triggered
  trusted-publishing job in `.github/workflows/ci.yml`
- Optional SECURITY.md and scope-guard rails for spray/knock in non-TTY use
