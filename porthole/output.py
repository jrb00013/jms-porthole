"""
Uniform structured output — a shared --json/--csv/-o option set for CLI
commands, built on top of report.py's existing to_json/to_csv helpers.

Usage in cli.py:

    @output_options
    def some_command(..., json_out, csv_out, output):
        ...
        emit(data, json_out=json_out, csv_out=csv_out, output=output, rows=rows)

`emit` prints the structured form to stdout when --json/--csv is passed
(instead of / in addition to the normal Rich table), and always writes to
--output/-o if given.
"""
import json as _json
import click

from .report import to_json, to_csv


def output_options(f):
    """Click decorator adding --json/--csv/-o to a command."""
    f = click.option("--json", "json_out", is_flag=True, default=False,
                      help="Print results as JSON to stdout")(f)
    f = click.option("--csv", "csv_out", is_flag=True, default=False,
                      help="Print results as CSV to stdout (list-shaped data only)")(f)
    f = click.option("-o", "--output", default=None,
                      help="Save results to this path (format inferred from --json/--csv, default JSON)")(f)
    return f


def emit(data, json_out: bool = False, csv_out: bool = False, output: str = None,
          rows: list[dict] = None) -> bool:
    """
    Emit `data` (or `rows` for CSV) per the requested format(s).

    Returns True if something was printed/written by this call, so the
    caller knows whether to skip its normal Rich-table rendering.
    """
    handled = False

    if json_out:
        print(_json.dumps(data, indent=2, default=str))
        handled = True

    if csv_out:
        csv_rows = rows if rows is not None else (data if isinstance(data, list) else None)
        if csv_rows:
            print(to_csv(csv_rows), end="")
            handled = True
        else:
            click.echo("(no rows to render as CSV)", err=True)

    if output:
        if output.endswith(".csv"):
            to_csv(rows if rows is not None else data, output)
        else:
            to_json(data, output)

    return handled
