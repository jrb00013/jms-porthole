from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from .ssh import SSHClient, test_connection

console = Console()


def probe_host(host: str, username: str, password: str) -> dict:
    result = {"host": host, "status": "unreachable", "os": "", "kernel": "",
              "cpu": "", "ram": "", "uptime": "", "users": "", "open_ports": ""}

    if not test_connection(host):
        return result

    try:
        with SSHClient(host, username, password) as ssh:
            result["status"] = "online"
            result["os"] = ssh.run_out(
                "lsb_release -d 2>/dev/null | cut -d: -f2 | xargs || "
                "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"
            )
            result["kernel"] = ssh.run_out("uname -r")
            result["cpu"] = ssh.run_out("nproc")
            result["ram"] = ssh.run_out("free -h | awk '/^Mem:/{print $2}'")
            result["uptime"] = ssh.run_out("uptime -p 2>/dev/null | sed 's/up //'")
            result["users"] = ssh.run_out("who | wc -l")
            result["open_ports"] = ssh.run_out(
                "ss -tlnp | awk 'NR>1{print $4}' | grep -oP ':\\K\\d+' | sort -n | tr '\\n' ',' | sed 's/,$//'"
            )
    except Exception as e:
        result["status"] = f"auth failed"

    return result


def harvest(hosts: list[str], username: str, password: str, threads: int = 10) -> list[dict]:
    results = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task(f"Harvesting {len(hosts)} host(s)...", total=len(hosts))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(probe_host, h, username, password): h for h in hosts}
            for future in as_completed(futures):
                progress.advance(task)
                results.append(future.result())

    return sorted(results, key=lambda r: r["host"])


def print_harvest_results(results: list[dict]):
    table = Table(title="[bold]🌾 Harvest Results[/bold]", border_style="cyan", expand=True)
    table.add_column("Host", style="bold cyan")
    table.add_column("Status")
    table.add_column("OS")
    table.add_column("CPU", justify="right")
    table.add_column("RAM", justify="right")
    table.add_column("Uptime")
    table.add_column("Users", justify="right")
    table.add_column("Open Ports")

    for r in results:
        status_color = "green" if r["status"] == "online" else "red" if r["status"] == "unreachable" else "yellow"
        table.add_row(
            r["host"],
            f"[{status_color}]{r['status']}[/{status_color}]",
            r["os"][:30] if r["os"] else "—",
            r["cpu"] or "—",
            r["ram"] or "—",
            r["uptime"] or "—",
            r["users"] or "—",
            r["open_ports"] or "—",
        )

    console.print(table)
    online = sum(1 for r in results if r["status"] == "online")
    console.print(f"[bold]{online}/{len(results)} host(s) accessible[/bold]")
