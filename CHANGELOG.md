# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions prior to
this document are reconstructed from git history.

## [0.3.0] — 2026-09-28

### Fixed
- Invalid `setuptools` build backend (`setuptools.backends.legacy:build` →
  `setuptools.build_meta`) that broke every `pip install` and red-failed CI
  on `main`.
- `jms --version` now reports the package version from `porthole.core`
  (was hard-coded `0.1.0`).
- `resolve_port_preset()` returns a copy so callers cannot mutate shared
  preset lists.
- Alert loop renders `ERR` (not `None`) when an HTTP check has no status.

### Added
- Expanded pytest suite (~935 tests, ≥70% coverage floor) covering alert,
  cert, creds, diff, harvest, monitor, probe, procs, report, secrets, ssh,
  sysinfo, tunnel, vuln, watcher, and CLI smoke (`--help` for every command).
- CI: ruff lint + format check, multi-Python matrix with coverage gate,
  wheel build + `jms --help` / `jms --version` smoke test; optional PyPI
  publish on `v*` tags.
- README documents profiles, `--json`/`--csv`, daemon mode, `diff --history`,
  keyring, fleet flags, and an authorized-use statement.

### Changed
- Package version bumped to `0.3.0`.
- Dev extras now include `pytest-cov`, `ruff`, and `build`.

## [0.2.0]

### Added
- `docs/ROADMAP.md` and `docs/IMPLEMENTATION_PLAN.md` describing the
  project's current state and planned work.
- `tests/` — a pytest suite covering `scanner.py`, `health.py`, `dns.py`,
  `profiles.py`, `output.py`, `fleet.py`, `store.py`, `keyring_store.py`,
  `config.py`, `spray.py`, `sinks.py`, `alert.py`, and `schedule_util.py`.
- **Config profiles** (`porthole/profiles.py`, `jms profile add/list/show/remove`):
  named host groups under `~/.porthole/profiles/*.yaml` with default ports,
  username, timeout, and jump-host.
- **Uniform structured output** (`porthole/output.py`): a shared
  `--json`/`--csv`/`-o` option set, wired into `scan`, `health`, `vuln`,
  and `netmap`.
- **Persistent results store** (`porthole/store.py`): a SQLite history at
  `~/.porthole/history.db` recording every `scan`/`vuln`/`netmap` run;
  `jms diff HOST --history --kind scan` diffs the current stored run
  against the previous one (`porthole/diff.py:diff_against_history`).
- **Fleet-wide parallel execution** (`porthole/fleet.py`):
  `--hosts-file`/`--parallel N` wired into `jms health`, and later extended
  to `scan`, `spray`, `netmap`, and `procs ps`.
- **Real vault/keyring integration**: `keyring_store.py` hardened with an
  `is_available()` check; `config.py` now stores/resolves host-alias
  passwords through the OS keyring first, falling back to (explicitly
  flagged) plaintext JSON only when no keyring backend is usable; `jms spray
  --save-hits` persists valid credential hits to the keyring instead of
  only a plaintext `-o` file. `keyring` and `PyYAML` are now real
  `pyproject.toml` dependencies.
- **Alerting sinks beyond stdout** (`porthole/sinks.py`): `WebhookSink`,
  `SlackSink`, and `EmailSink` behind a common `Sink` interface;
  `jms alert` fans out to any number of `--webhook`/`--extra-webhook`/
  `--email-to` sinks per run.
- **Scheduled/daemon mode**: `porthole/schedule_util.py` parses
  human-friendly durations (`30s`, `5m`, `1h`, `2d`); `jms daemon HOST
  --interval 5m --checks tcp:22` wraps the alert loop for unattended
  health monitoring (named `daemon`, not `watch`, since `jms watch` already
  tails a remote file).
- This `CHANGELOG.md`.
- GitHub Actions CI workflow running pytest on push/PR.

### Changed
- `porthole/alert.py`'s payload-building was refactored into
  `porthole/sinks.py`; `run_alert_loop` now takes a list of sinks instead
  of a single hardcoded webhook/Slack branch (backward compatible via the
  `webhook`/`slack` convenience arguments).

## [0.1.0]
- `docs`: add MIT license, rewrite README with full command reference and examples.
- `feat(diff)`: compare local vs remote files or two remote files with
  syntax-highlighted diff.
- `feat(health)`: HTTP and TCP health checks with latency measurement.
- `feat(creds)`: default credential wordlist and file-based wordlist loader
  for `spray`.
- `feat(scan)`: `--preset` flag (web/db/remote/devops/all) for quick port
  group scanning.
- `chore`: expose package metadata from `__init__`.
- `fix(broadcast)`: auto-detect display socket, add status check, fix xauth
  fallback.
- `feat(scanner)`: port preset shortcuts, progress bar, more common ports.
- `feat(cli)`: wire probe, transfer, spray, knock, netmap, traceroute, host
  aliases, `-o` output flag.
- `feat(report)`: export results to JSON, CSV, and Markdown.
- `feat(keyring)`: optional system keyring integration for secure
  credential storage.
- `feat(netmap)`: network mapping with ICMP ping, reverse DNS, and traceroute.
- `feat(portknock)`: TCP/UDP port knock sequence sender.
- `feat(spray)`: SSH credential spray for authorized pentesting and
  credential auditing.
- `feat(transfer)`: SFTP upload/download with progress bar and remote
  directory listing.
- `feat(probe)`: service fingerprinting with banner grab, TLS cert info,
  version detection.
- `feat(config)`: host alias store at `~/.config/jms/hosts.json`.
- `feat(ssh)`: SSH key auth, retry logic, upload/download helpers.
- `feat`: rebrand to JMS Porthole (Janus Monitoring Suite), add `jms` CLI
  entry point.
- Initial commit: porthole remote monitoring & recon toolkit.
