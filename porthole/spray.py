"""
SSH credential testing across a list of hosts.
For authorized penetration testing and credential auditing only.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from .ssh import SSHClient, test_connection

console = Console()


def _try_credential(host: str, port: int, username: str, password: str, timeout: int = 5) -> dict:
    result = {"host": host, "username": username, "password": password, "success": False, "error": ""}

    if not test_connection(host, port, timeout=2):
        result["error"] = "unreachable"
        return result

    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        client.close()
        result["success"] = True
    except paramiko.AuthenticationException:
        result["error"] = "auth failed"
    except Exception as e:
        result["error"] = str(e)[:60]

    return result


def spray_hosts(hosts: list[str], usernames: list[str], passwords: list[str],
                port: int = 22, threads: int = 10) -> list[dict]:
    """Test each (host, username, password) combination."""
    combos = [(h, u, p) for h in hosts for u in usernames for p in passwords]
    results = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task(f"Testing {len(combos)} credential combinations...", total=len(combos))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_try_credential, h, port, u, pw): (h, u, pw) for h, u, pw in combos}
            for future in as_completed(futures):
                progress.advance(task)
                results.append(future.result())

    return results


def print_spray_results(results: list[dict]):
    hits = [r for r in results if r["success"]]
    misses = [r for r in results if not r["success"]]

    if hits:
        table = Table(title="[bold green]Valid Credentials[/bold green]", border_style="green")
        table.add_column("Host", style="bold cyan")
        table.add_column("Username", style="green")
        table.add_column("Password", style="yellow")
        for r in hits:
            table.add_row(r["host"], r["username"], r["password"])
        console.print(table)
    else:
        console.print("[yellow]No valid credentials found.[/yellow]")

    console.print(f"\n[bold]{len(hits)} hit(s)[/bold] / {len(results)} tested")
