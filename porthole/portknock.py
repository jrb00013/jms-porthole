"""
Port knocking — send a sequence of connection attempts to trigger firewall rules.
"""
import socket
import time
from rich.console import Console

console = Console()


def knock(host: str, ports: list[int], protocol: str = "tcp", delay: float = 0.1):
    """Send a port knock sequence to HOST."""
    console.print(f"[cyan]Knocking {host}: {' → '.join(map(str, ports))}[/cyan]")

    for port in ports:
        try:
            if protocol == "tcp":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((host, port))
                s.close()
            elif protocol == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b"\x00", (host, port))
                s.close()
            console.print(f"  [dim]→ {port}/{protocol}[/dim]")
        except Exception:
            console.print(f"  [dim]→ {port}/{protocol}[/dim]")
        time.sleep(delay)

    console.print(f"[green]Knock sequence sent.[/green]")
