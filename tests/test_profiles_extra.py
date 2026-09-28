"""Extra unit tests for porthole.profiles — profile merge/resolve semantics and
the print_profiles / print_profile renderers.

PROFILES_DIR is redirected to tmp_path (never the real ~/.porthole) and the
Rich console is captured into a StringIO so table output is deterministic.
"""

import io

import pytest
from rich.console import Console

from porthole import profiles


@pytest.fixture
def profiles_dir(tmp_path, monkeypatch):
    d = tmp_path / "profiles"
    monkeypatch.setattr(profiles, "PROFILES_DIR", d)
    return d


@pytest.fixture
def console_buf(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(profiles, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_load_profile_merges_explicit_values_over_defaults(profiles_dir):
    profiles_dir.mkdir(parents=True)
    (profiles_dir / "partial.yaml").write_text("username: deploy\nports:\n  - 80\n  - 443\n")

    merged = profiles.load_profile("partial")

    assert merged["username"] == "deploy"
    assert merged["ports"] == [80, 443]
    # keys absent from the YAML keep DEFAULT_PROFILE values
    assert merged["timeout"] == 10
    assert merged["jump_host"] is None
    assert merged["hosts"] == []


def test_load_profile_explicit_zero_timeout_overrides_default(profiles_dir):
    profiles_dir.mkdir(parents=True)
    (profiles_dir / "fast.yaml").write_text("timeout: 0\n")

    assert profiles.load_profile("fast")["timeout"] == 0


def test_load_profile_treats_empty_yaml_file_as_all_defaults(profiles_dir):
    profiles_dir.mkdir(parents=True)
    (profiles_dir / "empty.yaml").write_text("")

    assert profiles.load_profile("empty") == profiles.DEFAULT_PROFILE


def test_save_profile_stores_empty_ports_list_when_ports_omitted(profiles_dir):
    path = profiles.save_profile("nohosts", hosts=[], username="root")

    saved = profiles.load_profile("nohosts")
    assert saved["ports"] == []
    assert saved["hosts"] == []
    assert saved["username"] == "root"
    assert saved["timeout"] == 10
    assert saved["jump_host"] is None
    assert path.name == "nohosts.yaml"


def test_save_profile_round_trips_jump_host_and_timeout(profiles_dir):
    profiles.save_profile(
        "bastion",
        hosts=["a", "b"],
        username="ops",
        ports=[22],
        timeout=45,
        jump_host="jump.example.com",
    )

    saved = profiles.load_profile("bastion")
    assert saved["jump_host"] == "jump.example.com"
    assert saved["timeout"] == 45
    assert saved["ports"] == [22]


def test_print_profiles_reports_empty_state_when_none_saved(profiles_dir, console_buf):
    profiles.print_profiles()

    assert "No profiles saved." in console_buf.getvalue()


def test_print_profiles_renders_sorted_rows_with_all_columns(profiles_dir, console_buf):
    profiles.save_profile("zeta", hosts=["10.0.0.2"], username="root", ports=[22])
    profiles.save_profile(
        "alpha",
        hosts=["10.0.0.1", "10.0.0.3"],
        username="deploy",
        ports=[80, 443],
        jump_host="jump.example.com",
    )

    profiles.print_profiles()

    out = console_buf.getvalue()
    assert "Profiles" in out
    for header in ("Name", "Hosts", "User", "Ports", "Jump host"):
        assert header in out
    assert "alpha" in out and "zeta" in out
    assert "10.0.0.1, 10.0.0.3" in out
    assert "80, 443" in out
    assert "jump.example.com" in out
    assert out.index("alpha") < out.index("zeta")


def test_print_profiles_shows_placeholder_dash_for_unset_fields(profiles_dir, console_buf):
    profiles.save_profile("bare", hosts=[])

    profiles.print_profiles()

    out = console_buf.getvalue()
    assert "bare" in out
    assert out.count("—") >= 3, "expected em-dash placeholders for user/ports/jump host"


def test_print_profile_reports_error_for_unknown_profile(profiles_dir, console_buf):
    profiles.print_profile("ghost")

    assert "No profile named 'ghost'" in console_buf.getvalue()


def test_print_profile_renders_every_field_of_a_saved_profile(profiles_dir, console_buf):
    profiles.save_profile(
        "prod",
        hosts=["10.0.0.1", "10.0.0.2"],
        username="deploy",
        ports=[80, 443],
        timeout=30,
        jump_host="bastion.example.com",
    )

    profiles.print_profile("prod")

    out = console_buf.getvalue()
    assert "prod" in out
    assert "hosts:     10.0.0.1, 10.0.0.2" in out
    assert "username:  deploy" in out
    assert "ports:     80, 443" in out
    assert "timeout:   30" in out
    assert "jump_host: bastion.example.com" in out


def test_print_profile_uses_dash_for_optional_fields_left_unset(profiles_dir, console_buf):
    profiles.save_profile("minimal", hosts=["10.0.0.9"], timeout=5)

    profiles.print_profile("minimal")

    out = console_buf.getvalue()
    assert "hosts:     10.0.0.9" in out
    assert "username:  —" in out
    assert "ports:     —" in out
    assert "timeout:   5" in out
    assert "jump_host: —" in out
