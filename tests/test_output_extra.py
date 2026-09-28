"""Extra unit tests for porthole.output — the output_options Click decorator
and emit()'s multi-format dispatch.

Nothing here touches the network; file writes go to tmp_path only.
"""

import csv
import io
import json

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from porthole import output, report


@pytest.fixture(autouse=True)
def _silence_report_console(monkeypatch):
    """`report.to_json/to_csv` print a 'saved to' line on their own Rich console;
    park it on a StringIO so stdout assertions only see emit()'s own output."""
    monkeypatch.setattr(report, "console", Console(file=io.StringIO(), width=200))


def _click_command(callback):
    """Wrap a callback in a real Click command carrying @output_options."""
    return click.command()(output.output_options(callback))


def test_output_options_adds_json_csv_and_output_params_to_a_command():
    @_click_command
    def probe(**kwargs):
        click.echo(json.dumps({k: v for k, v in kwargs.items()}, default=str))

    param_names = {p.name for p in probe.params}
    assert {"json_out", "csv_out", "output"} <= param_names

    by_name = {p.name: p for p in probe.params}
    assert by_name["json_out"].is_flag is True
    assert by_name["json_out"].default is False
    assert by_name["csv_out"].is_flag is True
    assert by_name["csv_out"].default is False
    assert by_name["output"].default is None
    assert set(by_name["output"].opts) == {"-o", "--output"}


def test_output_options_document_the_flags_in_command_help():
    @_click_command
    def probe(**kwargs):
        pass

    result = CliRunner().invoke(probe, ["--help"])

    assert result.exit_code == 0
    assert "--json" in result.output
    assert "--csv" in result.output
    assert "-o, --output" in result.output


def test_output_options_defaults_all_flags_off_when_none_passed():
    @_click_command
    def probe(**kwargs):
        click.echo(json.dumps(kwargs))

    result = CliRunner().invoke(probe, [])

    assert result.exit_code == 0
    assert json.loads(result.output) == {"json_out": False, "csv_out": False, "output": None}


def test_output_options_parses_short_and_long_output_flags(tmp_path):
    long_path = tmp_path / "long.json"
    short_path = tmp_path / "short.json"

    @_click_command
    def probe(**kwargs):
        click.echo(json.dumps(kwargs))

    long_result = CliRunner().invoke(probe, ["-o", str(long_path)])
    short_result = CliRunner().invoke(probe, ["--output", str(short_path)])

    assert long_result.exit_code == 0
    assert json.loads(long_result.output)["output"] == str(long_path)
    assert json.loads(short_result.output)["output"] == str(short_path)


def test_output_options_parses_json_and_csv_flags_together():
    @_click_command
    def probe(**kwargs):
        click.echo(json.dumps(kwargs))

    result = CliRunner().invoke(probe, ["--json", "--csv"])

    assert result.exit_code == 0
    assert json.loads(result.output) == {"json_out": True, "csv_out": True, "output": None}


def test_emit_writes_json_to_stdout_and_csv_to_file_when_both_requested(tmp_path, capsys):
    rows = [{"host": "10.0.0.1", "port": 22}]
    path = tmp_path / "out.csv"

    handled = output.emit(rows, json_out=True, csv_out=True, output=str(path), rows=rows)

    out = capsys.readouterr().out
    json_part, _, csv_part = out.partition("host,port")
    assert json.loads(json_part) == rows
    assert csv_part.strip() == "10.0.0.1,22"
    assert path.read_text().splitlines()[0] == "host,port"
    assert handled is True


def test_emit_uses_the_data_list_for_csv_when_rows_argument_is_omitted(capsys):
    rows = [{"host": "10.0.0.2", "port": 80}]

    handled = output.emit(rows, csv_out=True)

    out = capsys.readouterr().out
    assert "host,port" in out
    assert "10.0.0.2,80" in out
    assert handled is True


def test_emit_writes_csv_file_from_data_list_when_rows_is_none(tmp_path):
    rows = [{"host": "10.0.0.3", "port": 443}]
    path = tmp_path / "data.csv"

    output.emit(rows, output=str(path))

    written = list(csv.DictReader(io.StringIO(path.read_text())))
    assert written == [{"host": "10.0.0.3", "port": "443"}]


def test_emit_writes_json_file_even_when_stdout_format_is_none(tmp_path, capsys):
    path = tmp_path / "report.json"

    handled = output.emit({"count": 2}, output=str(path))

    assert json.loads(path.read_text()) == {"count": 2}
    assert capsys.readouterr().out == ""
    # nothing was printed, so the caller should still render its own table
    assert handled is False


def test_emit_prefers_explicit_rows_over_data_for_csv_file(tmp_path):
    data = [{"wrong": "column"}]
    rows = [{"host": "10.0.0.4", "port": 22}]
    path = tmp_path / "explicit.csv"

    output.emit(data, output=str(path), rows=rows)

    assert path.read_text().splitlines()[0] == "host,port"
    assert "wrong" not in path.read_text()


def test_emit_serialises_non_json_serialisable_data_with_default_str(tmp_path):
    path = tmp_path / "path.json"
    from pathlib import Path

    output.emit({"db": Path("/tmp/example.db")}, json_out=True, output=str(path))

    assert json.loads(path.read_text()) == {"db": "/tmp/example.db"}


def test_emit_writes_file_for_even_a_non_csv_non_json_extension(tmp_path):
    path = tmp_path / "results.txt"

    output.emit({"a": 1}, output=str(path))

    assert json.loads(path.read_text()) == {"a": 1}
