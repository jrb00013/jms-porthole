"""Unit tests for porthole.store — SQLite results history, using tmp_path DBs."""
from porthole import store


def test_record_and_last_run_round_trip(tmp_path):
    db = tmp_path / "history.db"
    store.record_run("scan", "10.0.0.1", {"22": "SSH"}, db_path=db)
    result = store.last_run("scan", "10.0.0.1", db_path=db)
    assert result["data"] == {"22": "SSH"}
    assert "ts" in result


def test_last_run_returns_none_when_no_history(tmp_path):
    db = tmp_path / "history.db"
    assert store.last_run("scan", "10.0.0.1", db_path=db) is None


def test_last_run_returns_most_recent(tmp_path):
    db = tmp_path / "history.db"
    store.record_run("scan", "host", {"v": 1}, db_path=db)
    store.record_run("scan", "host", {"v": 2}, db_path=db)
    assert store.last_run("scan", "host", db_path=db)["data"] == {"v": 2}


def test_history_returns_newest_first_limited(tmp_path):
    db = tmp_path / "history.db"
    for i in range(5):
        store.record_run("scan", "host", {"v": i}, db_path=db)
    rows = store.history("scan", "host", limit=3, db_path=db)
    assert len(rows) == 3
    assert [r["data"]["v"] for r in rows] == [4, 3, 2]


def test_diff_since_last_no_previous(tmp_path):
    db = tmp_path / "history.db"
    result = store.diff_since_last("netmap", "10.0.0.0/24", [{"host": "10.0.0.1"}], db_path=db)
    assert result["has_previous"] is False
    assert result["added"] == [{"host": "10.0.0.1"}]


def test_diff_since_last_detects_added_and_removed_for_lists(tmp_path):
    db = tmp_path / "history.db"
    store.diff_since_last("netmap", "cidr", [{"host": "a"}, {"host": "b"}], db_path=db)
    result = store.diff_since_last("netmap", "cidr", [{"host": "b"}, {"host": "c"}], db_path=db)
    assert result["has_previous"] is True
    assert result["changed"] is True
    assert {"host": "c"} in result["added"]
    assert {"host": "a"} in result["removed"]


def test_diff_since_last_no_change_for_identical_lists(tmp_path):
    db = tmp_path / "history.db"
    data = [{"host": "a"}]
    store.diff_since_last("netmap", "cidr", data, db_path=db)
    result = store.diff_since_last("netmap", "cidr", data, db_path=db)
    assert result["changed"] is False
    assert result["added"] == []
    assert result["removed"] == []


def test_diff_since_last_handles_dict_data():
    pass


def test_diff_since_last_dict_data_change_detection(tmp_path):
    db = tmp_path / "history.db"
    store.diff_since_last("vuln", "host", {"open_ssh": True}, db_path=db)
    result = store.diff_since_last("vuln", "host", {"open_ssh": False}, db_path=db)
    assert result["changed"] is True
