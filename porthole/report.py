"""
Report generation — export scan/harvest/sysinfo results to JSON, CSV, or Markdown.
"""
import json
import csv
import io
from datetime import datetime
from pathlib import Path
from rich.console import Console

console = Console()


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def to_json(data: dict | list, path: str = None) -> str:
    out = json.dumps(data, indent=2, default=str)
    if path:
        Path(path).write_text(out)
        console.print(f"[green]Report saved to {path}[/green]")
    return out


def to_csv(rows: list[dict], path: str = None) -> str:
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    out = buf.getvalue()
    if path:
        Path(path).write_text(out)
        console.print(f"[green]CSV saved to {path}[/green]")
    return out


def to_markdown(title: str, rows: list[dict], path: str = None) -> str:
    if not rows:
        return ""

    keys = list(rows[0].keys())
    lines = [f"# {title}", f"_Generated {datetime.now().isoformat()}_", ""]
    lines.append("| " + " | ".join(keys) + " |")
    lines.append("| " + " | ".join(["---"] * len(keys)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(k, "")) for k in keys) + " |")

    out = "\n".join(lines)
    if path:
        Path(path).write_text(out)
        console.print(f"[green]Markdown saved to {path}[/green]")
    return out


def auto_save(data: dict | list, prefix: str, fmt: str = "json"):
    path = f"jms_{prefix}_{_timestamp()}.{fmt}"
    if fmt == "json":
        to_json(data, path)
    elif fmt == "csv" and isinstance(data, list):
        to_csv(data, path)
    elif fmt == "md" and isinstance(data, list):
        to_markdown(prefix, data, path)
    return path
