"""
Remote file diff — compare a local file against a remote file, or two remote files.
"""

import difflib
import os

from rich.console import Console
from rich.syntax import Syntax

console = Console()


def diff_local_remote(host: str, username: str, password: str, local_path: str, remote_path: str):
    from .ssh import SSHClient

    local_path = os.path.expanduser(local_path)
    with open(local_path) as f:
        local_lines = f.readlines()

    with SSHClient(host, username, password) as ssh:
        remote_content = ssh.run_out(f"cat {remote_path}")

    remote_lines = [l + "\n" for l in remote_content.splitlines()]

    diff = list(
        difflib.unified_diff(
            local_lines,
            remote_lines,
            fromfile=f"local:{local_path}",
            tofile=f"{host}:{remote_path}",
        )
    )

    if not diff:
        console.print("[green]Files are identical.[/green]")
        return

    diff_text = "".join(diff)
    console.print(Syntax(diff_text, "diff", theme="monokai", line_numbers=False))


def diff_against_history(kind: str, target: str, current_data) -> None:
    """
    Diff `current_data` (e.g. a fresh scan/vuln/netmap result) against the
    last stored run of the same (kind, target) in the persistent results
    store, printing what was added/removed. Always records the new run.
    """
    from .store import diff_since_last

    result = diff_since_last(kind, target, current_data)

    if not result["has_previous"]:
        console.print(
            f"[dim]No previous '{kind}' run recorded for {target} — this run is now the baseline.[/dim]"
        )
        return

    if not result["changed"]:
        console.print(
            f"[green]No change since last '{kind}' run for {target} "
            f"({result['previous_ts']}).[/green]"
        )
        return

    console.print(
        f"[yellow]Changes since last '{kind}' run for {target} ({result['previous_ts']}):[/yellow]"
    )
    for item in result["added"] or []:
        console.print(f"  [green]+ {item}[/green]")
    for item in result["removed"] or []:
        console.print(f"  [red]- {item}[/red]")


def diff_remote_remote(host: str, username: str, password: str, path_a: str, path_b: str):
    from .ssh import SSHClient

    with SSHClient(host, username, password) as ssh:
        a = ssh.run_out(f"cat {path_a}")
        b = ssh.run_out(f"cat {path_b}")

    lines_a = [l + "\n" for l in a.splitlines()]
    lines_b = [l + "\n" for l in b.splitlines()]

    diff = list(difflib.unified_diff(lines_a, lines_b, fromfile=path_a, tofile=path_b))

    if not diff:
        console.print("[green]Files are identical.[/green]")
        return

    diff_text = "".join(diff)
    console.print(Syntax(diff_text, "diff", theme="monokai", line_numbers=False))
