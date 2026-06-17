"""
Remote log search — grep journalctl and log files on remote hosts.
"""
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from .ssh import SSHClient

console = Console()


def search_journal(host: str, username: str, password: str,
                   pattern: str, since: str = "1 hour ago",
                   unit: str = None, limit: int = 100) -> list[dict]:
    unit_filter = f"-u {unit}" if unit else ""
    cmd = (
        f"journalctl --since '{since}' {unit_filter} --no-pager 2>/dev/null "
        f"| grep -i '{pattern}' | tail -{limit}"
    )

    with SSHClient(host, username, password) as ssh:
        raw = ssh.run_out(cmd, timeout=60)

    return _parse_lines(raw, source="journal")


def search_files(host: str, username: str, password: str,
                 pattern: str, paths: list[str] = None,
                 limit: int = 100) -> list[dict]:
    paths = paths or ["/var/log"]
    path_str = " ".join(paths)
    cmd = (
        f"grep -rni --include='*.log' --include='syslog' --include='messages' "
        f"-m {limit} '{pattern}' {path_str} 2>/dev/null | head -{limit}"
    )

    with SSHClient(host, username, password) as ssh:
        raw = ssh.run_out(cmd, timeout=120)

    results = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        parts = line.split(":", 2)
        if len(parts) >= 3:
            results.append({
                "file": parts[0],
                "line": parts[1],
                "text": parts[2].strip(),
                "source": "file",
            })
    return results


def search_all(host: str, username: str, password: str,
               pattern: str, since: str = "1 hour ago",
               paths: list[str] = None, limit: int = 100) -> list[dict]:
    journal = search_journal(host, username, password, pattern, since, limit=limit)
    files = search_files(host, username, password, pattern, paths, limit=limit)
    combined = journal + files
    return combined[:limit]


def _parse_lines(raw: str, source: str = "journal") -> list[dict]:
    results = []
    for line in raw.splitlines():
        if line.strip():
            results.append({"text": line.strip(), "source": source})
    return results


def print_search_results(host: str, pattern: str, results: list[dict]):
    if not results:
        console.print(f"[dim]No matches for '{pattern}' on {host}[/dim]")
        return

    console.print(f"[cyan]{len(results)} matches for [bold]{pattern}[/bold] on {host}[/cyan]\n")

    for r in results:
        if r.get("file"):
            console.print(f"[bold cyan]{r['file']}:{r['line']}[/bold cyan]")
            console.print(f"  {r['text'][:200]}")
        else:
            console.print(r["text"][:200])
        console.print()
