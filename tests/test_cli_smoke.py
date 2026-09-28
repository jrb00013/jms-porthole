"""Smoke tests for the porthole.cli Click application.

Every leaf command in the Click tree is walked recursively and invoked with
``--help`` through ``click.testing.CliRunner``. That exercises every decorator
line in the 1000+ line cli.py at import/registration time, so a command whose
options/imports are broken fails here instead of at the user's terminal.

No command body performs real network I/O here: ``--help`` short-circuits
before the command callback runs.
"""

import json
import re
from pathlib import Path

import click
import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib
from click.testing import CliRunner

from porthole import config
from porthole.cli import get_credentials, main, resolve_host
from porthole.core import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _walk(cmd, path):
    """Return (group_paths, leaf_paths) as space-joined arg paths under `cmd`."""
    groups, leaves = [], []
    subcommands = getattr(cmd, "commands", None)
    if subcommands is None:
        return groups, [path]
    if path:
        groups.append(path)
    for name in sorted(subcommands):
        child_path = f"{path} {name}" if path else name
        child_groups, child_leaves = _walk(subcommands[name], child_path)
        groups.extend(child_groups)
        leaves.extend(child_leaves)
    return groups, leaves


GROUP_PATHS, LEAF_PATHS = _walk(main, "")


def test_command_tree_walk_finds_every_registered_leaf_command():
    assert len(LEAF_PATHS) >= 30, "command tree walk is broken — too few leaves discovered"
    assert GROUP_PATHS == ["dns", "hosts", "procs", "profile"]
    for expected_group in ("dns", "hosts", "procs", "profile"):
        assert expected_group in GROUP_PATHS
    for expected_leaf in ("scan", "health", "alert", "sysinfo", "logsearch", "daemon"):
        assert expected_leaf in LEAF_PATHS


@pytest.mark.parametrize("path", LEAF_PATHS, ids=LEAF_PATHS)
def test_every_leaf_command_help_succeeds_and_documents_usage(path):
    result = CliRunner().invoke(main, [*path.split(), "--help"])

    assert result.exit_code == 0, (
        f"`jms {path} --help` failed: {result.output!r} {result.exception!r}"
    )
    assert result.output.strip(), f"`jms {path} --help` produced no output"
    assert "Usage:" in result.output
    assert path.split()[-1] in result.output


@pytest.mark.parametrize("path", GROUP_PATHS, ids=GROUP_PATHS)
def test_every_group_command_help_succeeds_and_lists_subcommands(path):
    result = CliRunner().invoke(main, [*path.split(), "--help"])

    assert result.exit_code == 0, f"`jms {path} --help` failed: {result.output!r}"
    assert "Usage:" in result.output
    group = main.commands[path]
    for name in group.commands:
        assert name in result.output, f"`jms {path} --help` omits subcommand {name}"


def test_top_level_help_succeeds_and_lists_every_group_and_leaf():
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    missing = [name for name in main.commands if name not in result.output]
    assert missing == [], f"top-level --help omits registered commands: {missing}"


def test_top_level_short_help_flag_works_because_help_option_names_configured():
    long_form = CliRunner().invoke(main, ["--help"])
    short_form = CliRunner().invoke(main, ["-h"])

    assert short_form.exit_code == 0
    assert short_form.output == long_form.output


def test_no_args_prints_help_and_exits_with_usage_error_code():
    result = CliRunner().invoke(main, [])

    # Click's no_args_is_help on a Group prints help. Exit code is 2 on modern
    # Click (usage error) and 0 on some older Click builds still pulled on 3.9.
    assert result.exit_code in (0, 2)
    assert "Usage:" in result.output
    assert "COMMAND [ARGS]" in result.output


def test_version_option_reports_core_version():
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"jms, version {__version__}"


def test_version_option_matches_pyproject_version_field():
    pyproject_version = tomllib.loads(PYPROJECT.read_text())["project"]["version"]

    result = CliRunner().invoke(main, ["--version"])

    assert result.output.strip() == f"jms, version {pyproject_version}"
    assert __version__ == pyproject_version, (
        "porthole.core.__version__ has drifted from pyproject.toml [project].version"
    )


def test_unknown_command_exits_with_click_usage_error():
    result = CliRunner().invoke(main, ["definitely-not-a-command"])

    assert result.exit_code != 0
    assert "No such command" in result.output


def test_scan_command_rejects_invalid_preset_value():
    result = CliRunner().invoke(main, ["scan", "10.0.0.1", "--preset", "nonsense"])

    assert result.exit_code != 0
    assert "nonsense" in result.output


def _readme_command_entries():
    """Extract the `jms ...` command codes from the README command table."""
    table = re.findall(r"^\|\s*`(jms [^`]+)`\s*\|", README.read_text(), re.MULTILINE)
    return [code for code in (row.removeprefix("jms ").strip() for row in table) if code]


README_CODES = _readme_command_entries()


def test_readme_command_table_was_parsed():
    assert len(README_CODES) >= 25, "README command table extraction failed"


@pytest.mark.parametrize("code", README_CODES, ids=README_CODES)
def test_readme_documented_command_exists_and_help_works(code):
    name = code.split()[0]

    assert name in main.commands, f"README documents `jms {code}` but no such command exists"

    result = CliRunner().invoke(main, [name, "--help"])
    assert result.exit_code == 0, f"README-documented `jms {code}` has a broken --help"
    assert "Usage:" in result.output


@pytest.mark.parametrize(
    "group,subs",
    [
        ("procs", ["services", "ps", "restart", "kill"]),
        ("dns", ["lookup", "enum", "reverse"]),
        ("hosts", ["add", "list", "remove"]),
    ],
    ids=["procs", "dns", "hosts"],
)
def test_readme_slash_listed_subcommands_all_exist(group, subs):
    group_cmd = main.commands[group]
    missing = [sub for sub in subs if sub not in group_cmd.commands]

    assert missing == [], f"README lists `jms {group} {'/'.join(subs)}` but missing: {missing}"
    for sub in subs:
        result = CliRunner().invoke(main, [group, sub, "--help"])
        assert result.exit_code == 0


def test_get_credentials_prompts_for_missing_username_and_password(monkeypatch):
    prompts = []

    def fake_prompt(text, **kwargs):
        prompts.append((text, kwargs))
        return {"Username": "admin", "Password": "s3cret"}[text]

    monkeypatch.setattr(click, "prompt", fake_prompt)

    assert get_credentials(None, None) == ("admin", "s3cret")
    assert [p[0] for p in prompts] == ["Username", "Password"]
    assert prompts[1][1] == {"hide_input": True}


def test_get_credentials_prompts_only_for_the_missing_field(monkeypatch):
    calls = []
    monkeypatch.setattr(click, "prompt", lambda text, **kw: calls.append(text) or "prompted")

    assert get_credentials("root", None) == ("root", "prompted")
    assert calls == ["Password"]


def test_get_credentials_prompts_for_nothing_when_both_supplied(monkeypatch):
    monkeypatch.setattr(
        click, "prompt", lambda text, **kw: pytest.fail(f"unexpected prompt: {text}")
    )

    assert get_credentials("root", "pw") == ("root", "pw")


def test_resolve_host_replaces_alias_with_saved_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")
    (tmp_path / "hosts.json").write_text(
        json.dumps(
            {
                "web": {
                    "host": "10.0.0.7",
                    "username": "deploy",
                    "password": "pw7",
                    "port": 2222,
                    "keyring": False,
                }
            }
        )
    )

    assert resolve_host("web", "ignored", "ignored-pw") == ("10.0.0.7", "deploy", "pw7")


def test_resolve_host_falls_back_to_raw_host_when_alias_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")

    assert resolve_host("10.0.0.9", "root", "pw") == ("10.0.0.9", "root", "pw")


def test_resolve_host_prefers_passed_credentials_when_saved_entry_has_blank_fields(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")
    (tmp_path / "hosts.json").write_text(
        json.dumps({"bare": {"host": "10.0.0.8", "username": "", "password": "", "port": 22}})
    )

    assert resolve_host("bare", "root", "fallback-pw") == ("10.0.0.8", "root", "fallback-pw")
