# Roadmap

Status: living document. Reflects the state of `jms-porthole` as of 2026-08-17,
after auditing `README.md`, `pyproject.toml`, every module under `porthole/`,
and the git history (40 commits, all `feat(cli)`/`feat(<module>)` additions,
zero tests, no CHANGELOG prior to this document).

## Current state

`jms-porthole` (aka JMS — Janus Monitoring Suite) is a single-package Click
CLI (`porthole/cli.py`, ~790 lines, one `@main.command()` per subcommand)
wrapping paramiko SSH sessions. It has 30 subcommands covering monitoring,
VNC broadcast, port scanning, service fingerprinting, credential spraying,
DNS/health/vuln checks, log search, and webhook alerting. The code is fully
wired end to end — no stubs or TODOs — but has these structural gaps:

- **Zero automated tests.** No `tests/` directory, no `pytest` config, no CI.
  Every module (`scanner.py`, `health.py`, `dns.py`, `spray.py`, ...) is only
  exercised by hand against real hosts.
- **No fleet-wide execution for most commands.** `harvest.py` and the
  `exec`/`spray` paths already use `ThreadPoolExecutor` across a host list,
  and `scanner.scan_network` parallelizes port checks within one CIDR — but
  `health`, `procs`, `netmap`, and `vuln` only take a single host today, and
  there is no `--hosts-file` / `--parallel N` convention shared across
  commands.
- **Inconsistent output formats.** `report.py` provides `to_json`/`to_csv`/
  `to_markdown` and several commands accept `-o FILE` for JSON, but there is
  no uniform `--json`/`--csv` flag applied consistently, and most commands
  only render Rich tables to stdout.
- **No persistent results history.** `diff.py` only diffs two files given at
  invocation time; there is no stored history of past `scan`/`vuln`/`netmap`
  runs to diff against, so "what changed since last week" is not answerable.
- **Plaintext credential handling.** `config.py` stores host aliases
  (including passwords) in `~/.config/jms/hosts.json`, chmod'd 0600 — better
  than nothing, but plaintext on disk. `keyring_store.py` exists and wraps
  the `keyring` package, but nothing in `cli.py` or `spray.py` calls it —
  credentials always flow through `--password`/prompts/`config.py` in the
  clear, and `spray.py` (credential-spraying tool) never persists results
  through the keyring path either. `keyring` is not declared as a project
  dependency.
- **No named host-group config.** `config.py` only supports single-host
  aliases (`hosts add/list/remove`); there's no profile concept for a group
  of hosts sharing default ports, credentials, timeouts, or jump-hosts.
- **Alerting is stdout + single webhook only.** `alert.py`'s
  `run_alert_loop` renders a live Rich table and can POST a JSON or
  Slack-shaped payload to one `--webhook` URL. There's no email sink, no
  multiple-sink fan-out, and no reusable "sink" abstraction — the Slack vs.
  generic branching is a single `if slack` flag baked into `_build_*_payload`.
- **No daemon/scheduled mode.** `alert` already loops on an interval in the
  foreground; there is no `porthole watch --interval 5m` wrapping
  `monitor.py`/`health.py` as a detachable background process, and no
  human-friendly duration parsing (`5m`, `1h`) — `alert --interval` takes
  raw seconds only.
- **No CHANGELOG.** Every one of the 40 commits is additive and follows a
  loose `feat(<module>): ...` convention, but nothing renders that history
  for end users.

## Planned work

Ordered roughly by leverage-per-effort (see `docs/IMPLEMENTATION_PLAN.md`
for the exact commit sequence):

1. **Test suite (`tests/`, pytest).** Lock down the pure-logic parts of
   `scanner.py` (port/preset tables), `health.py` (`parse_check_specs`),
   and `dns.py` (record/subdomain shaping) before anything else changes,
   so later refactors have a safety net. Network-touching functions are
   tested with mocked sockets/subprocess, not real hosts.
2. **Config profiles (`~/.porthole/profiles/*.yaml`).** Named host groups
   with default ports, credentials (referencing the vault, never plaintext),
   timeouts, and an optional jump-host, loaded via a new `porthole/profiles.py`
   and a `jms profile` subcommand group.
3. **Uniform structured output.** A shared `--json`/`--csv` option
   (`porthole/output.py`) applied consistently across `scan`, `health`,
   `vuln`, `dns`, `netmap`, and `spray`, built on the existing `report.py`
   helpers instead of each command hand-rolling `-o`.
4. **Persistent results store.** A local SQLite store under
   `~/.porthole/history.db` (`porthole/store.py`) that `scan`/`vuln`/`netmap`
   write a snapshot to on every run, giving `diff.py` a real
   `jms diff --history HOST` mode that diffs against the last stored run
   instead of only two ad-hoc files.
5. **Fleet-wide parallel execution.** A shared `--hosts-file`/`--parallel N`
   convention (`porthole/fleet.py`, built on `concurrent.futures`, mirroring
   the pattern already proven in `harvest.py`/`spray.py`) extended to
   `health`, `procs`, and `netmap`.
6. **Real vault integration.** Make `keyring_store.py` the actual credential
   path: `config.py`/`spray.py`/`cli.py` resolve passwords through the OS
   keyring first (with the existing plaintext JSON as an explicit, warned
   fallback), and declare `keyring` as a real dependency in `pyproject.toml`.
7. **Alerting sinks beyond stdout.** Generalize `alert.py`'s payload
   builders into a `Sink` interface (`porthole/sinks.py`) with `webhook`,
   `slack`, and `email` (`smtplib`) implementations, fanning out to any
   number of configured sinks per alert run.
8. **Daemon/scheduled mode.** A `jms watch HOST --interval 5m` command
   wrapping `health.py`/`monitor.py` with human-friendly duration parsing,
   reusing the loop structure already proven in `alert.run_alert_loop`.
9. **CHANGELOG.md.** Reconstructed from the 40 existing commits plus every
   commit landing on this branch, in Keep-a-Changelog format, updated going
   forward.

## Explicitly out of scope for this pass

Full `asyncssh` migration, a `pass`/HashiCorp Vault backend, and CI
workflow files are noted as good future follow-ups but are not required to
land the above — see the "Deferred" section of the PR description for what
was and wasn't completed in this iteration.
