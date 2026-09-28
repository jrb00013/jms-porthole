"""Unit tests for porthole.report — JSON/CSV/Markdown export written into tmp_path."""

import csv
import io
import json
import re
from datetime import datetime
from pathlib import Path

from porthole import report

NESTED = {
    "host": "10.0.4.21",
    "ports": [22, 80, 443],
    "nested": {"cpu": 12.5, "tags": ["a", "b"], "gateway": None},
    "missing": None,
}

ROWS = [
    {"host": "10.0.0.1", "port": 22, "state": "open", "note": None},
    {"host": "10.0.0.2", "port": 80, "state": "closed", "note": "timeout"},
]


def read(path):
    return Path(path).read_text()


def test_to_json_round_trips_nested_dicts_lists_and_none():
    out = report.to_json(NESTED)
    assert json.loads(out) == NESTED
    assert '"tags": [' in out
    assert '"gateway": null' in out


def test_to_json_formats_output_with_two_space_indent():
    out = report.to_json({"a": 1})
    assert out == json.dumps({"a": 1}, indent=2)
    assert '\n  "a": 1' in out


def test_to_json_accepts_a_list_of_records():
    out = report.to_json(ROWS)
    assert json.loads(out) == ROWS
    assert out.startswith("[\n")


def test_to_json_serializes_non_json_types_as_strings():
    stamp = datetime(2026, 9, 28, 12, 0, 0)
    out = report.to_json({"ts": stamp, "path": Path("/tmp/x")})
    assert json.loads(out) == {"ts": "2026-09-28 12:00:00", "path": "/tmp/x"}


def test_to_json_writes_file_to_given_path(tmp_path):
    target = tmp_path / "report.json"
    out = report.to_json(NESTED, str(target))
    assert read(target) == out
    assert json.loads(target.read_text()) == NESTED


def test_to_json_without_path_writes_nothing_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report.to_json(NESTED)
    assert list(tmp_path.iterdir()) == []


def test_to_csv_writes_header_and_all_rows():
    out = report.to_csv(ROWS)
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert parsed == [
        {"host": "10.0.0.1", "port": "22", "state": "open", "note": ""},
        {"host": "10.0.0.2", "port": "80", "state": "closed", "note": "timeout"},
    ]
    assert out.splitlines()[0] == "host,port,state,note"


def test_to_csv_serializes_none_values_as_empty_cells():
    out = report.to_csv([{"a": None, "b": 1}])
    assert out.splitlines()[1] == ",1"


def test_to_csv_uses_first_row_keys_as_fieldnames():
    out = report.to_csv([{"a": 1, "b": 2}, {"a": 3}])
    assert out.splitlines()[0] == "a,b"
    assert out.splitlines()[2] == "3,"


def test_to_csv_returns_empty_string_for_no_rows():
    assert report.to_csv([]) == ""


def test_to_csv_with_no_rows_does_not_create_a_file(tmp_path):
    target = tmp_path / "empty.csv"
    assert report.to_csv([], str(target)) == ""
    assert target.exists() is False


def test_to_csv_writes_file_to_given_path(tmp_path):
    target = tmp_path / "rows.csv"
    out = report.to_csv(ROWS, str(target))
    # csv writes \r\n terminators, so compare bytes to avoid newline translation
    assert target.read_bytes() == out.encode()
    assert "10.0.0.1,22,open," in target.read_text()


def test_to_markdown_builds_title_generated_line_and_table():
    out = report.to_markdown("Open Ports", ROWS)
    lines = out.splitlines()

    assert lines[0] == "# Open Ports"
    assert re.fullmatch(r"_Generated \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?_", lines[1])
    assert lines[2] == ""
    assert lines[3] == "| host | port | state | note |"
    assert lines[4] == "| --- | --- | --- | --- |"
    assert lines[5] == "| 10.0.0.1 | 22 | open | None |"
    assert lines[6] == "| 10.0.0.2 | 80 | closed | timeout |"


def test_to_markdown_renders_none_as_the_literal_string_none():
    out = report.to_markdown("t", [{"a": None}])
    assert out.splitlines()[-1] == "| None |"


def test_to_markdown_renders_missing_key_as_blank_cell():
    out = report.to_markdown("t", [{"a": 1, "b": 2}, {"a": 3}])
    assert out.splitlines()[-1] == "| 3 |  |"


def test_to_markdown_returns_empty_string_for_no_rows():
    assert report.to_markdown("Nothing", []) == ""


def test_to_markdown_with_no_rows_does_not_create_a_file(tmp_path):
    target = tmp_path / "empty.md"
    assert report.to_markdown("Nothing", [], str(target)) == ""
    assert target.exists() is False


def test_to_markdown_writes_file_to_given_path(tmp_path):
    target = tmp_path / "ports.md"
    out = report.to_markdown("Open Ports", ROWS, str(target))
    assert read(target) == out
    assert target.read_text().startswith("# Open Ports")


def test_auto_save_json_writes_timestamped_file_in_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(NESTED, "sysinfo", "json")

    assert re.fullmatch(r"jms_sysinfo_\d{8}_\d{6}\.json", path)
    written = read(tmp_path / path)
    assert json.loads(written) == NESTED


def test_auto_save_csv_writes_list_data_to_timestamped_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(ROWS, "ports", "csv")

    assert re.fullmatch(r"jms_ports_\d{8}_\d{6}\.csv", path)
    assert read(tmp_path / path).splitlines()[0] == "host,port,state,note"


def test_auto_save_markdown_uses_prefix_as_title(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(ROWS, "ports", "md")

    assert re.fullmatch(r"jms_ports_\d{8}_\d{6}\.md", path)
    body = read(tmp_path / path)
    assert body.startswith("# ports\n")
    assert "| host | port | state | note |" in body


def test_auto_save_csv_ignores_non_list_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(NESTED, "sysinfo", "csv")

    assert re.fullmatch(r"jms_sysinfo_\d{8}_\d{6}\.csv", path)
    assert (tmp_path / path).exists() is False


def test_auto_save_markdown_ignores_non_list_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(NESTED, "sysinfo", "md")

    assert re.fullmatch(r"jms_sysinfo_\d{8}_\d{6}\.md", path)
    assert (tmp_path / path).exists() is False


def test_auto_save_unknown_format_creates_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(ROWS, "ports", "txt")

    assert path == re.fullmatch(r"jms_ports_\d{8}_\d{6}\.txt", path).group(0)
    assert list(tmp_path.iterdir()) == []


def test_auto_save_json_handles_list_payload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save(ROWS, "ports", "json")
    assert json.loads(read(tmp_path / path)) == ROWS


def test_auto_save_defaults_to_json_format(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = report.auto_save({"a": 1}, "quick")
    assert path.endswith(".json")
    assert json.loads(read(tmp_path / path)) == {"a": 1}


def test_timestamp_format_is_sortable_utc_free_local_time():
    stamp = report._timestamp()
    assert re.fullmatch(r"\d{8}_\d{6}", stamp)
    datetime.strptime(stamp, "%Y%m%d_%H%M%S")
