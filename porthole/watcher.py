import time
from rich.console import Console
from rich.text import Text
from .ssh import SSHClient

console = Console()

HIGHLIGHT_PATTERNS = {
    "error": "bold red",
    "fail": "bold red",
    "warn": "bold yellow",
    "warning": "bold yellow",
    "success": "bold green",
    "ok": "bold green",
    "info": "cyan",
    "critical": "bold red reverse",
    "traceback": "red",
    "exception": "bold red",
}


def colorize_line(line: str) -> Text:
    text = Text(line)
    lower = line.lower()
    for pattern, style in HIGHLIGHT_PATTERNS.items():
        if pattern in lower:
            text.stylize(style)
            break
    return text


def watch_file(host: str, username: str, password: str, filepath: str, lines: int = 50):
    """Tail -f a file on the remote host with live colorized output."""
    console.print(f"[cyan]Watching [bold]{filepath}[/bold] on {host}...[/cyan]")
    console.print("[dim]Ctrl+C to stop[/dim]\n")

    with SSHClient(host, username, password) as ssh:
        transport = ssh._client.get_transport()
        chan = transport.open_session()
        chan.get_pty()
        chan.exec_command(f"tail -n {lines} -f {filepath}")

        buffer = ""
        try:
            while True:
                if chan.recv_ready():
                    chunk = chan.recv(4096).decode(errors="replace")
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        console.print(colorize_line(line))
                elif chan.exit_status_ready():
                    break
                else:
                    time.sleep(0.05)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped.[/yellow]")
        finally:
            chan.close()


def watch_logs(host: str, username: str, password: str, service: str = None):
    """Watch journalctl logs, optionally filtered by service."""
    cmd = "journalctl -f --no-pager"
    if service:
        cmd += f" -u {service}"

    label = f"journalctl{f' -u {service}' if service else ''}"
    console.print(f"[cyan]Watching [bold]{label}[/bold] on {host}...[/cyan]")
    console.print("[dim]Ctrl+C to stop[/dim]\n")

    with SSHClient(host, username, password) as ssh:
        transport = ssh._client.get_transport()
        chan = transport.open_session()
        chan.get_pty()
        chan.exec_command(cmd)

        buffer = ""
        try:
            while True:
                if chan.recv_ready():
                    chunk = chan.recv(4096).decode(errors="replace")
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        console.print(colorize_line(line))
                elif chan.exit_status_ready():
                    break
                else:
                    time.sleep(0.05)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped.[/yellow]")
        finally:
            chan.close()
