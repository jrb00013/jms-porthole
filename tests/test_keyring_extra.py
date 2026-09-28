"""Extra unit tests for porthole.keyring_store — availability branches, typed
returns, and failure handling.

A fake in-memory backend stands in for the OS keyring everywhere. The only
place the real `keyring` package is involved at all is the ImportError test,
which blocks the import with ``sys.modules["keyring"] = None`` and reloads the
module in-process — no real keyring backend is ever queried or written to.
"""

import importlib
import io
import sys

from rich.console import Console

from porthole import keyring_store


class FakeKeyring:
    """Minimal in-memory stand-in for a real keyring backend."""

    def __init__(self):
        self._data = {}

    def set_password(self, service, key, password):
        self._data[(service, key)] = password

    def get_password(self, service, key):
        return self._data.get((service, key))

    def delete_password(self, service, key):
        del self._data[(service, key)]


def _capture(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(keyring_store, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_module_reports_no_keyring_when_the_keyring_package_cannot_be_imported():
    saved_keyring = sys.modules.get("keyring")
    saved_errors = sys.modules.get("keyring.errors")
    sys.modules["keyring"] = None
    try:
        reloaded = importlib.reload(keyring_store)
        assert reloaded.HAS_KEYRING is False
        assert reloaded._keyring is None
        # the exception aliases degrade to bare Exception so the module still imports
        assert reloaded.KeyringError is Exception
        assert reloaded.NoKeyringError is Exception
        assert reloaded.is_available() is False
        assert reloaded.SERVICE == "jms-porthole"
    finally:
        if saved_keyring is None:
            sys.modules.pop("keyring", None)
        else:
            sys.modules["keyring"] = saved_keyring
        if saved_errors is not None:
            sys.modules["keyring.errors"] = saved_errors
        importlib.reload(keyring_store)


def test_real_module_state_is_restored_after_the_import_error_reload():
    # guards the reload test above: the shared module object must be usable again
    assert keyring_store.HAS_KEYRING is True
    assert keyring_store._keyring is not None
    assert keyring_store.KeyringError is not Exception
    assert keyring_store.NoKeyringError is not Exception


def test_is_available_false_when_get_keyring_raises(monkeypatch):
    class Exploding:
        def get_keyring(self):
            raise RuntimeError("no dbus session")

    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", Exploding())

    assert keyring_store.is_available() is False


def test_store_password_keys_entries_by_service_and_alias_user(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", fake)
    monkeypatch.setattr(keyring_store, "is_available", lambda: True)

    assert keyring_store.store_password("myhost", "admin", "s3cret") is True
    assert fake._data == {(keyring_store.SERVICE, "myhost:admin"): "s3cret"}
    assert keyring_store.SERVICE == "jms-porthole"


def test_store_password_returns_false_and_warns_when_backend_raises(monkeypatch):
    class Broken:
        def set_password(self, service, key, password):
            raise RuntimeError("backend locked")

    buf = _capture(monkeypatch)
    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", Broken())
    monkeypatch.setattr(keyring_store, "is_available", lambda: True)

    assert keyring_store.store_password("myhost", "admin", "pw") is False
    out = buf.getvalue()
    assert "Keyring store failed" in out
    assert "falling back to plain config" in out


def test_store_password_warns_about_fallback_when_no_backend_is_usable(monkeypatch):
    buf = _capture(monkeypatch)
    monkeypatch.setattr(keyring_store, "is_available", lambda: False)

    assert keyring_store.store_password("myhost", "admin", "pw") is False
    assert "No usable OS keyring backend" in buf.getvalue()
    assert "fall back to plain config" in buf.getvalue()


def test_get_password_returns_none_when_backend_raises(monkeypatch):
    class Broken:
        def get_password(self, service, key):
            raise RuntimeError("backend locked")

    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", Broken())
    monkeypatch.setattr(keyring_store, "is_available", lambda: True)

    assert keyring_store.get_password("myhost", "admin") is None


def test_get_password_returns_none_for_unknown_entry_in_working_backend(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", fake)
    monkeypatch.setattr(keyring_store, "is_available", lambda: True)

    assert keyring_store.get_password("myhost", "admin") is None


def test_delete_password_removes_entry_and_returns_true(monkeypatch):
    fake = FakeKeyring()
    fake.set_password(keyring_store.SERVICE, "myhost:admin", "pw")
    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", fake)

    assert keyring_store.delete_password("myhost", "admin") is True
    assert fake._data == {}


def test_delete_password_false_when_backend_raises_non_keyring_error(monkeypatch):
    class Broken:
        def delete_password(self, service, key):
            raise ValueError("unexpected")

    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", Broken())

    assert keyring_store.delete_password("myhost", "admin") is False


def test_delete_password_ignores_is_available_and_only_checks_install(monkeypatch):
    """delete_password gates on HAS_KEYRING, unlike store/get which gate on is_available."""
    fake = FakeKeyring()
    fake.set_password(keyring_store.SERVICE, "myhost:admin", "pw")
    monkeypatch.setattr(keyring_store, "HAS_KEYRING", True)
    monkeypatch.setattr(keyring_store, "_keyring", fake)
    monkeypatch.setattr(keyring_store, "is_available", lambda: False)

    assert keyring_store.delete_password("myhost", "admin") is True
    assert fake._data == {}
