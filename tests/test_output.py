"""Unit tests for porthole.output — shared --json/--csv/-o emission."""

import json

from porthole import output


def test_emit_json_prints_and_returns_handled(capsys):
    handled = output.emit({"a": 1}, json_out=True)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"a": 1}
    assert handled is True


def test_emit_csv_prints_rows(capsys):
    rows = [{"host": "a", "port": 22}, {"host": "b", "port": 80}]
    handled = output.emit(rows, csv_out=True, rows=rows)
    captured = capsys.readouterr()
    assert "host,port" in captured.out
    assert "a,22" in captured.out
    assert handled is True


def test_emit_no_flags_does_nothing(capsys):
    handled = output.emit({"a": 1})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert handled is False


def test_emit_writes_json_file(tmp_path):
    path = tmp_path / "out.json"
    output.emit({"a": 1}, output=str(path))
    assert json.loads(path.read_text()) == {"a": 1}


def test_emit_writes_csv_file_when_path_ends_csv(tmp_path):
    path = tmp_path / "out.csv"
    rows = [{"a": 1, "b": 2}]
    output.emit(rows, output=str(path), rows=rows)
    content = path.read_text()
    assert "a,b" in content
    assert "1,2" in content


def test_emit_csv_with_no_rows_warns_but_does_not_crash(capsys):
    handled = output.emit({}, csv_out=True)
    captured = capsys.readouterr()
    assert "no rows" in captured.err
    assert handled is False
