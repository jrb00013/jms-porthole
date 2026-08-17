# Implementation Plan

Concrete, ordered, commit-sized steps implementing `docs/ROADMAP.md`. Each
numbered step is intended to be one commit (or a very small handful),
buildable and working in isolation. Priority order: tests first, then
config profiles, then structured output, then results store, then parallel
execution, then vault integration, then alerting sinks, then daemon mode,
then CHANGELOG.

1. `chore:` add `tests/` scaffolding — `pytest` dev dependency in
   `pyproject.toml`, `tests/__init__.py`, `pytest.ini`/`[tool.pytest.ini_options]`.
2. `test:` cover `scanner.py` — `check_port`/`grab_banner` behavior via
   mocked sockets, `scan_ports` port-preset resolution, `resolve_port_preset`.
3. `test:` cover `health.py` — `parse_check_specs` for `tcp:`, `http:`,
   `https:` forms including path handling and malformed specs.
4. `test:` cover `dns.py` — record shaping in `lookup_records`/`_dig`
   parsing (mocked `subprocess.run`), `enumerate_subdomains` filtering.
5. `feat(profiles):` add `porthole/profiles.py` — load/save/list/resolve
   named host-group profiles from `~/.porthole/profiles/*.yaml` (ports,
   users, timeouts, jump-host, credential ref).
6. `feat(cli):` wire `jms profile add/list/show/remove` subcommands.
7. `test:` cover `profiles.py` load/save/resolve round-trip with a tmp dir.
8. `feat(output):` add `porthole/output.py` — a shared `emit(data, fmt,
   path)` helper plus a `@output_options` Click decorator adding
   `--json`/`--csv`/`-o` uniformly.
9. `feat(cli):` apply `--json`/`--csv` to `scan`, `health`, `dns`, `vuln`,
   `netmap` via the new decorator, replacing ad-hoc `-o` handling.
10. `feat(store):` add `porthole/store.py` — SQLite-backed results history
    at `~/.porthole/history.db` with `record_run(kind, host, data)` and
    `last_run(kind, host)`/`diff_since_last(kind, host, data)`.
11. `feat(diff):` extend `diff.py` with `diff_against_history` and wire a
    `jms diff --history HOST --kind scan` CLI mode.
12. `test:` cover `store.py` record/retrieve/diff round-trip with a tmp
    sqlite file.
13. `feat(fleet):` add `porthole/fleet.py` — `run_over_hosts(hosts, fn,
    parallel=N)` built on `concurrent.futures.ThreadPoolExecutor`, plus a
    `--hosts-file`/`--parallel` Click decorator.
14. `feat(cli):` wire fleet execution into `health` and `netmap` commands
    (multi-host mode alongside existing single-host behavior).
15. `feat(vault):` harden `keyring_store.py` (explicit availability check,
    typed return, `is_available()`), add `keyring` to `pyproject.toml`
    dependencies, and make `config.resolve`/`spray` prefer the keyring
    before falling back to plaintext JSON with a visible warning.
16. `test:` cover `keyring_store.py` with a fake in-memory backend
    (no real OS keyring in CI).
17. `feat(alert):` refactor `alert.py` payload building into
    `porthole/sinks.py` (`WebhookSink`, `SlackSink`, `EmailSink`, `Sink`
    protocol) and fan out `run_alert_loop` to a list of configured sinks.
18. `feat(cli):` add `--email` / multiple `--webhook` support to the
    `alert` command using the new sinks.
19. `feat(watch):` add `porthole/schedule_util.py` (human duration parsing:
    `5m`, `1h`, `30s`) and a `jms watch HOST --interval 5m` command wrapping
    `health.run_health_checks`/`monitor` on a loop.
20. `test:` cover `schedule_util.py` duration parsing edge cases.
21. `docs: ` add `CHANGELOG.md` reconstructed from the pre-existing 40
    commits plus this branch's commits, Keep-a-Changelog format.
22. `chore:` run full `pytest` + any existing lint, fix fallout, final
    polish pass before opening the PR.

Deferred (documented, not implemented this pass): `asyncssh`/true async
fleet execution, `pass`/HashiCorp Vault backend, CI workflow files, JSONL
alternative to SQLite for the results store.
