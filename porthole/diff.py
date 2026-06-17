"""
Remote file diff — compare a local file against a remote file, or two remote files.
"""
import difflib
import tempfile
import os
from rich.console import Console
from rich.syntax import Syntax

console = Console()


def diff_local_remote(host: str, username: str, password: str,
                      local_path: str, remote_path: str):
    from .ssh import SSHClient

    local_path = os.path.expanduser(local_path)
    with open(local_path) as f:
        local_lines = f.readlines()

    with SSHClient(host, username, password) as ssh:
        remote_content = ssh.run_out(f"cat {remote_path}")

    remote_lines = [l + "\n" for l in remote_content.splitlines()]

    diff = list(difflib.unified_diff(
        local_lines, remote_lines,
        fromfile=f"local:{local_path}",
        tofile=f"{host}:{remote_path}",
    ))

    if not diff:
        console.print("[green]Files are identical.[/green]")
        return

    diff_text = "".join(diff)
    console.print(Syntax(diff_text, "diff", theme="monokai", line_numbers=False))


def diff_remote_remote(host: str, username: str, password: str,
                       path_a: str, path_b: str):
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
