"""Unit tests for porthole.keyring_store — uses a fake in-memory backend, never a real OS keyring."""

from unittest.mock import MagicMock, patch

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


def test_is_available_false_when_keyring_not_installed():
    with patch.object(keyring_store, "HAS_KEYRING", False):
        assert keyring_store.is_available() is False


def test_is_available_true_with_real_backend():
    fake_backend = MagicMock()
    type(fake_backend).__module__ = "keyring.backends.SecretService"
    type(fake_backend).__name__ = "Keyring"
    with (
        patch.object(keyring_store, "HAS_KEYRING", True),
        patch.object(keyring_store, "_keyring") as mock_kr,
    ):
        mock_kr.get_keyring.return_value = fake_backend
        assert keyring_store.is_available() is True


def test_is_available_false_for_fail_backend():
    class FailKeyring:
        pass

    FailKeyring.__module__ = "keyring.backends.fail"

    with (
        patch.object(keyring_store, "HAS_KEYRING", True),
        patch.object(keyring_store, "_keyring") as mock_kr,
    ):
        mock_kr.get_keyring.return_value = FailKeyring()
        assert keyring_store.is_available() is False


def test_store_and_get_password_round_trip():
    fake = FakeKeyring()
    with (
        patch.object(keyring_store, "HAS_KEYRING", True),
        patch.object(keyring_store, "_keyring", fake),
        patch.object(keyring_store, "is_available", return_value=True),
    ):
        assert keyring_store.store_password("myhost", "admin", "s3cret") is True
        assert keyring_store.get_password("myhost", "admin") == "s3cret"


def test_store_password_returns_false_when_unavailable():
    with patch.object(keyring_store, "is_available", return_value=False):
        assert keyring_store.store_password("myhost", "admin", "pw") is False


def test_get_password_returns_none_when_unavailable():
    with patch.object(keyring_store, "is_available", return_value=False):
        assert keyring_store.get_password("myhost", "admin") is None


def test_delete_password_swallows_missing_entry():
    with (
        patch.object(keyring_store, "HAS_KEYRING", True),
        patch.object(keyring_store, "_keyring") as mock_kr,
    ):
        mock_kr.delete_password.side_effect = Exception("not found")
        assert keyring_store.delete_password("myhost", "admin") is False


def test_delete_password_false_when_keyring_not_installed():
    with patch.object(keyring_store, "HAS_KEYRING", False):
        assert keyring_store.delete_password("myhost", "admin") is False
