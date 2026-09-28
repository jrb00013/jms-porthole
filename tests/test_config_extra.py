"""Extra unit tests for porthole.config — list/delete output paths and the
keyring-first vs plaintext-fallback credential resolution branches.

The config dir is redirected to tmp_path and porthole.keyring_store is always
patched, so no real ~/.config/jms file and no real OS keyring are touched.
"""

import io
import json
from unittest.mock import patch

from rich.console import Console

from porthole import config


def _capture(monkeypatch, module=config):
    """Redirect a module's Rich console into a wide, colourless StringIO."""
    buf = io.StringIO()
    monkeypatch.setattr(module, "console", Console(file=buf, width=200, no_color=True))
    return buf


def _redirect(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")


def test_delete_host_of_unknown_alias_prints_error_and_keeps_file_intact(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    config._save({"keep": {"host": "1.1.1.1", "username": "u", "password": "", "port": 22}})
    buf = _capture(monkeypatch)

    with patch("porthole.keyring_store.delete_password") as delete_mock:
        config.delete_host("not-saved")

    delete_mock.assert_not_called()
    assert "No host named 'not-saved'" in buf.getvalue()
    assert set(config._load()) == {"keep"}


def test_list_hosts_reports_no_saved_hosts_when_config_is_absent(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    buf = _capture(monkeypatch)

    config.list_hosts()

    assert "No saved hosts." in buf.getvalue()


def test_list_hosts_prints_empty_state_when_config_file_holds_empty_object(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    (tmp_path / "hosts.json").write_text("{}")
    buf = _capture(monkeypatch)

    config.list_hosts()

    assert "No saved hosts." in buf.getvalue()
    assert "Saved Hosts" not in buf.getvalue()


def test_list_hosts_renders_a_row_per_alias_with_port_and_user(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    (tmp_path / "hosts.json").write_text(
        json.dumps(
            {
                "zeta": {"host": "10.0.0.2", "username": "root", "password": "", "port": 2222},
                "alpha": {"host": "10.0.0.1", "username": "deploy", "password": "", "port": 22},
            }
        )
    )
    buf = _capture(monkeypatch)

    config.list_hosts()

    out = buf.getvalue()
    assert "Saved Hosts" in out
    assert "Alias" in out and "Host" in out and "User" in out and "Port" in out
    assert "10.0.0.1" in out and "10.0.0.2" in out
    assert "deploy" in out and "root" in out
    assert "2222" in out
    # sorted(data.items()) => alpha is rendered before zeta
    assert out.index("alpha") < out.index("zeta")


def test_list_hosts_defaults_missing_port_to_22(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    (tmp_path / "hosts.json").write_text(
        json.dumps({"legacy": {"host": "10.0.0.3", "username": "old"}})
    )
    buf = _capture(monkeypatch)

    config.list_hosts()

    out = buf.getvalue()
    assert "legacy" in out
    assert "10.0.0.3" in out
    assert "22" in out


def test_get_host_returns_saved_entry_dict_or_none(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    config._save({"a": {"host": "1.2.3.4", "username": "u", "password": "", "port": 2200}})

    assert config.get_host("a") == {
        "host": "1.2.3.4",
        "username": "u",
        "password": "",
        "port": 2200,
    }
    assert config.get_host("missing") is None


def test_resolve_uses_keyring_password_for_keyring_backed_entry(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    config._save(
        {
            "kr": {
                "host": "10.0.0.4",
                "username": "kruser",
                "password": "",
                "port": 22,
                "keyring": True,
            }
        }
    )

    with patch("porthole.keyring_store.get_password", return_value="from-keyring") as get_mock:
        assert config.resolve("kr") == ("10.0.0.4", "kruser", "from-keyring", 22)

    get_mock.assert_called_once_with("kr", "kruser")


def test_resolve_falls_back_to_stored_plaintext_when_keyring_lookup_returns_none(
    tmp_path, monkeypatch
):
    _redirect(monkeypatch, tmp_path)
    config._save(
        {
            "kr": {
                "host": "10.0.0.4",
                "username": "kruser",
                "password": "plain",
                "port": 22,
                "keyring": True,
            }
        }
    )

    with patch("porthole.keyring_store.get_password", return_value=None):
        assert config.resolve("kr") == ("10.0.0.4", "kruser", "plain", 22)


def test_resolve_never_consults_keyring_for_plaintext_entry(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    config._save({"plain": {"host": "10.0.0.5", "username": "u", "password": "pw", "port": 22}})

    with patch("porthole.keyring_store.get_password") as get_mock:
        assert config.resolve("plain") == ("10.0.0.5", "u", "pw", 22)

    get_mock.assert_not_called()


def test_resolve_defaults_port_to_22_when_entry_omits_it(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    (tmp_path / "hosts.json").write_text(
        json.dumps({"old": {"host": "10.0.0.6", "username": "u", "password": ""}})
    )

    assert config.resolve("old") == ("10.0.0.6", "u", "", 22)


def test_save_host_without_password_never_calls_the_keyring(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)

    with patch("porthole.keyring_store.store_password") as store_mock:
        config.save_host("keyonly", "10.0.0.7", "root", "")

    store_mock.assert_not_called()
    saved = config._load()["keyonly"]
    assert saved["password"] == ""
    assert saved["keyring"] is False


def test_save_host_warns_loudly_when_password_falls_back_to_plaintext(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    buf = _capture(monkeypatch)

    with patch("porthole.keyring_store.store_password", return_value=False):
        config.save_host("fallback", "10.0.0.8", "root", "hunter2")

    out = " ".join(buf.getvalue().split())
    assert "fallback" in out
    assert "plain config (no keyring backend available)" in out
    assert config._load()["fallback"]["password"] == "hunter2"


def test_save_host_reports_keyring_destination_when_keyring_accepted_password(
    tmp_path, monkeypatch
):
    _redirect(monkeypatch, tmp_path)
    buf = _capture(monkeypatch)

    with patch("porthole.keyring_store.store_password", return_value=True):
        config.save_host("secure", "10.0.0.9", "deploy", "s3cret", 2200)

    out = buf.getvalue()
    assert "OS keyring" in out
    assert "plain config" not in out
    assert "deploy@10.0.0.9:2200" in out


def test_saved_hosts_file_is_owner_read_write_only(tmp_path, monkeypatch):
    _redirect(monkeypatch, tmp_path)
    with patch("porthole.keyring_store.store_password", return_value=True):
        config.save_host("perm", "10.0.0.10", "root", "pw")

    mode = config.HOSTS_FILE.stat().st_mode & 0o777
    assert mode == 0o600
