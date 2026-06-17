import time
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from .ssh import SSHClient

console = Console()


def get_system_stats(ssh: SSHClient) -> dict:
    stats = {}

    # CPU
    cpu_raw = ssh.run_out("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
    stats["cpu"] = float(cpu_raw.replace(",", ".")) if cpu_raw else 0.0

    # Memory
    mem_raw = ssh.run_out("free -m | awk '/^Mem:/{print $2, $3, $4}'")
    if mem_raw:
        parts = mem_raw.split()
        stats["mem_total"] = int(parts[0])
        stats["mem_used"] = int(parts[1])
        stats["mem_free"] = int(parts[2])
    else:
        stats["mem_total"] = stats["mem_used"] = stats["mem_free"] = 0

    # Disk
    disk_raw = ssh.run_out("df -h / | awk 'NR==2{print $2, $3, $4, $5}'")
    if disk_raw:
        parts = disk_raw.split()
        stats["disk_total"] = parts[0]
        stats["disk_used"] = parts[1]
        stats["disk_free"] = parts[2]
        stats["disk_pct"] = parts[3]
    else:
        stats["disk_total"] = stats["disk_used"] = stats["disk_free"] = stats["disk_pct"] = "?"

    # Load average
    stats["load"] = ssh.run_out("cat /proc/loadavg | awk '{print $1, $2, $3}'")

    # Uptime
    stats["uptime"] = ssh.run_out("uptime -p 2>/dev/null || uptime")

    # Top processes
    procs_raw = ssh.run_out(
        "ps aux --sort=-%cpu | awk 'NR>1 && NR<=8{printf \"%s %s %s %s\\n\", $1, $3, $4, $11}'"
    )
    stats["procs"] = [p.split() for p in procs_raw.splitlines() if p]

    # Network connections
    stats["connections"] = ssh.run_out("ss -tn | grep ESTAB | wc -l")

    # Logged-in users
    stats["users"] = ssh.run_out("who | wc -l")

    return stats


def bar(pct: float, width: int = 20) -> str:
    filled = int(width * pct / 100)
    color = "green" if pct < 60 else "yellow" if pct < 85 else "red"
    bar_str = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar_str}[/{color}] {pct:.1f}%"


def build_display(host: str, stats: dict) -> Panel:
    mem_pct = (stats["mem_used"] / stats["mem_total"] * 100) if stats["mem_total"] else 0

    cpu_panel = Panel(
        f"[bold]CPU[/bold]  {bar(stats['cpu'])}\n"
        f"[bold]MEM[/bold]  {bar(mem_pct)} ({stats['mem_used']}M / {stats['mem_total']}M)\n"
        f"[bold]Load[/bold] {stats['load']}\n"
        f"[bold]Up[/bold]   {stats['uptime']}",
        title="Resources",
        border_style="cyan",
    )

    disk_panel = Panel(
        f"[bold]Used[/bold]  {stats['disk_used']} / {stats['disk_total']}\n"
        f"[bold]Free[/bold]  {stats['disk_free']}\n"
        f"[bold]Pct[/bold]   {stats['disk_pct']}",
        title="Disk /",
        border_style="blue",
    )

    net_panel = Panel(
        f"[bold]Connections[/bold]  {stats['connections']}\n"
        f"[bold]Users[/bold]        {stats['users']}",
        title="Network",
        border_style="green",
    )

    proc_table = Table(title="Top Processes", border_style="yellow", expand=True)
    proc_table.add_column("User", style="cyan")
    proc_table.add_column("CPU%", justify="right")
    proc_table.add_column("MEM%", justify="right")
    proc_table.add_column("Command")
    for proc in stats.get("procs", []):
        if len(proc) >= 4:
            proc_table.add_row(proc[0], proc[1], proc[2], proc[3])

    return Panel(
        Columns([cpu_panel, disk_panel, net_panel]) if False else
        f"{cpu_panel.renderable}\n\n"
        + str(proc_table),
        title=f"[bold]📡 porthole monitor — {host}[/bold]",
        border_style="bright_cyan",
    )


def run_monitor(host: str, username: str, password: str, interval: int = 3):
    console.print(f"[cyan]Connecting to {host}...[/cyan]")
    with SSHClient(host, username, password) as ssh:
        console.print("[green]Connected. Press Ctrl+C to stop.[/green]\n")
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                try:
                    stats = get_system_stats(ssh)
                    cpu_pct = stats["cpu"]
                    mem_pct = (stats["mem_used"] / stats["mem_total"] * 100) if stats["mem_total"] else 0

                    table = Table(title=f"[bold]📡 porthole monitor — {host}[/bold]", border_style="cyan", expand=True)
                    table.add_column("Metric", style="bold cyan", width=12)
                    table.add_column("Value")

                    table.add_row("CPU", bar(cpu_pct))
                    table.add_row("Memory", f"{bar(mem_pct)} ({stats['mem_used']}M / {stats['mem_total']}M)")
                    table.add_row("Disk", f"{stats['disk_used']} / {stats['disk_total']} ({stats['disk_pct']})")
                    table.add_row("Load", stats["load"])
                    table.add_row("Uptime", stats["uptime"])
                    table.add_row("Net conns", stats["connections"])
                    table.add_row("Users", stats["users"])

                    proc_table = Table(border_style="dim", expand=True, show_header=True)
                    proc_table.add_column("User", style="cyan", width=12)
                    proc_table.add_column("CPU%", justify="right", width=8)
                    proc_table.add_column("MEM%", justify="right", width=8)
                    proc_table.add_column("Command")
                    for proc in stats.get("procs", []):
                        if len(proc) >= 4:
                            proc_table.add_row(proc[0], proc[1], proc[2], proc[3])

                    from rich.console import Group
                    live.update(Group(table, proc_table))
                    time.sleep(interval)
                except KeyboardInterrupt:
                    break
