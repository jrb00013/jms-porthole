"""Unit tests for porthole.spray — credential combo generation and hit persistence."""

from unittest.mock import patch

from porthole import spray


def test_store_hits_in_keyring_only_stores_successes():
    results = [
        {"host": "a", "username": "admin", "password": "pw", "success": True},
        {"host": "b", "username": "root", "password": "pw2", "success": False},
    ]
    with patch("porthole.keyring_store.store_password", return_value=True) as store_mock:
        stored = spray.store_hits_in_keyring(results)

    assert stored == 1
    store_mock.assert_called_once_with("a", "admin", "pw")


def test_store_hits_in_keyring_counts_only_actual_successes():
    results = [
        {"host": "a", "username": "admin", "password": "pw", "success": True},
        {"host": "b", "username": "root", "password": "pw2", "success": True},
    ]
    with patch("porthole.keyring_store.store_password", side_effect=[True, False]):
        stored = spray.store_hits_in_keyring(results)
    assert stored == 1


def test_store_hits_in_keyring_empty_results():
    assert spray.store_hits_in_keyring([]) == 0


def test_try_credential_reports_unreachable_without_connecting():
    with patch.object(spray, "test_connection", return_value=False):
        result = spray._try_credential("10.0.0.1", 22, "admin", "pw")
    assert result["error"] == "unreachable"
    assert result["success"] is False
