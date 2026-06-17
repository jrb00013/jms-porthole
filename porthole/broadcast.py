import time
from rich.console import Console
from rich.panel import Panel
from .ssh import SSHClient

console = Console()


def start_broadcast(host: str, username: str, password: str) -> dict:
    """
    SSH into host, start x11vnc on the active X display, return connection info.
    Returns dict with host, port, display.
    """
    with SSHClient(host, username, password) as ssh:
        # Install x11vnc if missing
        out = ssh.run_out("command -v x11vnc")
        if not out:
            console.print("[yellow]Installing x11vnc...[/yellow]")
            ssh.run_sudo("apt-get update -qq")
            ssh.run_sudo("apt-get install -y x11vnc")

        # Kill any existing instance
        ssh.run("pkill -x x11vnc 2>/dev/null; sleep 1; true")

        # Detect display (X11 socket name)
        display_socket = ssh.run_out("ls /tmp/.X11-unix/ | head -1")
        display = ":" + display_socket.lstrip("X") if display_socket else ":0"

        # Find Xauthority
        xauth = ssh.run_out("ls /run/user/*/gdm/Xauthority 2>/dev/null | head -1")
        if not xauth:
            xauth = ssh.run_out("echo $HOME/.Xauthority")

        # Wake the display
        ssh.run(f"DISPLAY={display} XAUTHORITY={xauth} xset dpms force on 2>/dev/null; true")
        ssh.run(f"DISPLAY={display} XAUTHORITY={xauth} xset s reset 2>/dev/null; true")

        # Start x11vnc
        ssh.run(
            f"DISPLAY={display} XAUTHORITY={xauth} "
            f"nohup x11vnc -nopw -forever -noxfixes -noxdamage "
            f"> /tmp/x11vnc.log 2>&1 &"
        )
        time.sleep(3)

        # Verify
        pid = ssh.run_out("pgrep -x x11vnc")
        if not pid:
            log = ssh.run_out("cat /tmp/x11vnc.log | head -20")
            raise RuntimeError(f"x11vnc failed to start:\n{log}")

        # Detect port
        port_out = ssh.run_out(
            "ss -tlnp 2>/dev/null | grep x11vnc | grep -oP ':\\K\\d+' | head -1"
        )
        port = int(port_out) if port_out.isdigit() else 5901

        return {"host": host, "port": port, "display": display, "xauth": xauth}


def stop_broadcast(host: str, username: str, password: str):
    with SSHClient(host, username, password) as ssh:
        ssh.run("pkill -x x11vnc")
        console.print("[green]x11vnc stopped.[/green]")


def print_connection_info(info: dict):
    host, port = info["host"], info["port"]
    console.print(Panel(
        f"[bold cyan]Host:[/bold cyan]    {host}\n"
        f"[bold cyan]Port:[/bold cyan]    {port}\n"
        f"[bold cyan]Display:[/bold cyan] {info['display']}\n\n"
        f"[bold green]Connect:[/bold green]\n"
        f"  vncviewer {host}:{port}\n\n"
        f"[bold green]SSH tunnel:[/bold green]\n"
        f"  ssh -L {port}:localhost:{port} <user>@{host}\n"
        f"  vncviewer localhost:{port}",
        title="[bold]🖥️  DESKTOP BROADCASTING[/bold]",
        border_style="cyan",
    ))
