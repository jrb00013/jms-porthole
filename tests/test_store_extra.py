"""Extra unit tests for porthole.store — the before_id "compare against an
earlier snapshot" branch of last_run().

All databases live under tmp_path; no real ~/.porthole/history.db is opened.
"""

from porthole import store


def _seed(db, values, kind="scan", target="host"):
    return [store.record_run(kind, target, {"v": v}, db_path=db) for v in values]


def test_last_run_before_id_returns_the_newest_run_strictly_older_than_it(tmp_path):
    db = tmp_path / "history.db"
    ids = _seed(db, [1, 2, 3])

    result = store.last_run("scan", "host", db_path=db, before_id=ids[2])

    assert result["id"] == ids[1]
    assert result["data"] == {"v": 2}


def test_last_run_before_id_excludes_only_the_newer_row(tmp_path):
    db = tmp_path / "history.db"
    ids = _seed(db, [1, 2, 3])

    older = store.last_run("scan", "host", db_path=db, before_id=ids[1])
    newest = store.last_run("scan", "host", db_path=db)

    assert older["data"] == {"v": 1}
    assert newest["data"] == {"v": 3}


def test_last_run_before_id_returns_none_when_no_older_run_exists(tmp_path):
    db = tmp_path / "history.db"
    only_id = _seed(db, [1])[0]

    assert store.last_run("scan", "host", db_path=db, before_id=only_id) is None


def test_last_run_before_id_returns_none_for_unknown_kind_even_with_rows(tmp_path):
    db = tmp_path / "history.db"
    ids = _seed(db, [1, 2], kind="scan", target="host")

    assert store.last_run("vuln", "host", db_path=db, before_id=ids[1]) is None


def test_last_run_before_id_ignores_rows_for_a_different_target(tmp_path):
    db = tmp_path / "history.db"
    store.record_run("scan", "other-host", {"v": 99}, db_path=db)
    own = _seed(db, [1, 2], target="host")

    result = store.last_run("scan", "host", db_path=db, before_id=own[1])

    assert result["data"] == {"v": 1}


def test_last_run_before_id_zero_never_matches_any_row(tmp_path):
    db = tmp_path / "history.db"
    _seed(db, [1, 2])

    assert store.last_run("scan", "host", db_path=db, before_id=0) is None


def test_history_is_unaffected_by_before_id_filtering(tmp_path):
    db = tmp_path / "history.db"
    ids = _seed(db, [1, 2, 3])

    store.last_run("scan", "host", db_path=db, before_id=ids[1])
    rows = store.history("scan", "host", limit=3, db_path=db)

    assert [r["data"]["v"] for r in rows] == [3, 2, 1]
    assert [r["id"] for r in rows] == [ids[2], ids[1], ids[0]]


def test_diff_since_last_still_records_a_new_run_each_call(tmp_path):
    db = tmp_path / "history.db"
    store.diff_since_last("netmap", "cidr", [{"h": "a"}], db_path=db)
    store.diff_since_last("netmap", "cidr", [{"h": "a"}], db_path=db)

    rows = store.history("netmap", "cidr", limit=10, db_path=db)

    assert len(rows) == 2
    assert rows[0]["id"] > rows[1]["id"]


def test_record_run_serialises_non_json_types_with_default_str(tmp_path):
    db = tmp_path / "history.db"
    from pathlib import Path

    row_id = store.record_run("sysinfo", "host", {"root": Path("/etc")}, db_path=db)

    assert store.last_run("sysinfo", "host", db_path=db)["data"] == {"root": "/etc"}
    assert row_id > 0


def test_recorded_run_timestamps_are_utc_isoformat_strings(tmp_path):
    db = tmp_path / "history.db"
    store.record_run("scan", "host", {"v": 1}, db_path=db)

    ts = store.last_run("scan", "host", db_path=db)["ts"]

    assert ts.endswith("+00:00"), f"expected a UTC-aware ISO timestamp, got {ts!r}"
