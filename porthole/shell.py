import sys
import termios
import tty
import select
import socket
from rich.console import Console
from .ssh import SSHClient

console = Console()


def interactive_shell(host: str, username: str, password: str):
    """Drop into an interactive SSH shell on the remote host."""
    console.print(f"[cyan]Opening shell on {host} as {username}...[/cyan]")
    console.print("[dim]Type 'exit' or press Ctrl+D to close[/dim]\n")

    client = SSHClient(host, username, password).connect()
    chan = client._client.invoke_shell(term="xterm-256color", width=220, height=50)

    old_tty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                data = sys.stdin.buffer.read(1)
                if not data:
                    break
                chan.sendall(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        chan.close()
        client.disconnect()
        console.print("\n[yellow]Shell closed.[/yellow]")


def run_command_on_hosts(hosts: list[str], username: str, password: str, command: str):
    """Run a single command on multiple hosts and print results."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from rich.table import Table

    def run_on(host):
        try:
            with SSHClient(host, username, password) as ssh:
                out, err, code = ssh.run(command, timeout=15)
                return {"host": host, "output": out, "error": err, "code": code}
        except Exception as e:
            return {"host": host, "output": "", "error": str(e), "code": -1}

    table = Table(title=f"[bold]$ {command}[/bold]", border_style="cyan", expand=True)
    table.add_column("Host", style="bold cyan", width=20)
    table.add_column("Exit", justify="right", width=6)
    table.add_column("Output")

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(run_on, h): h for h in hosts}
        results = [f.result() for f in as_completed(futures)]

    results.sort(key=lambda r: r["host"])
    for r in results:
        color = "green" if r["code"] == 0 else "red"
        output = r["output"] or r["error"] or "[dim]—[/dim]"
        table.add_row(r["host"], f"[{color}]{r['code']}[/{color}]", output[:200])

    console.print(table)
