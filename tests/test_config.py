"""Unit tests for porthole.config — host aliases, keyring-first credential storage."""

from unittest.mock import patch

from porthole import config


def test_save_host_uses_keyring_and_omits_plaintext(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")

    with patch("porthole.keyring_store.store_password", return_value=True) as store_mock:
        config.save_host("myhost", "10.0.0.1", "admin", "s3cret", 22)

    store_mock.assert_called_once_with("myhost", "admin", "s3cret")
    saved = config._load()
    assert saved["myhost"]["password"] == ""
    assert saved["myhost"]["keyring"] is True


def test_save_host_falls_back_to_plaintext_when_keyring_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")

    with patch("porthole.keyring_store.store_password", return_value=False):
        config.save_host("myhost", "10.0.0.1", "admin", "s3cret", 22)

    saved = config._load()
    assert saved["myhost"]["password"] == "s3cret"
    assert saved["myhost"]["keyring"] is False


def test_resolve_reads_password_back_from_keyring(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")

    with patch("porthole.keyring_store.store_password", return_value=True):
        config.save_host("myhost", "10.0.0.1", "admin", "s3cret", 22)

    with patch("porthole.keyring_store.get_password", return_value="s3cret") as get_mock:
        resolved = config.resolve("myhost")

    get_mock.assert_called_once_with("myhost", "admin")
    assert resolved == ("10.0.0.1", "admin", "s3cret", 22)


def test_resolve_returns_none_for_unknown_alias(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")
    assert config.resolve("does-not-exist") is None


def test_delete_host_also_removes_keyring_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "HOSTS_FILE", tmp_path / "hosts.json")

    with patch("porthole.keyring_store.store_password", return_value=True):
        config.save_host("myhost", "10.0.0.1", "admin", "s3cret", 22)

    with patch("porthole.keyring_store.delete_password") as delete_mock:
        config.delete_host("myhost")

    delete_mock.assert_called_once_with("myhost", "admin")
    assert config.get_host("myhost") is None
