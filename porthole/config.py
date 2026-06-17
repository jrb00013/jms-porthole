"""
Config file support: ~/.config/jms/hosts.json
Lets you save hosts with credentials so you don't retype them.
"""
import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

CONFIG_DIR = Path.home() / ".config" / "jms"
HOSTS_FILE = CONFIG_DIR / "hosts.json"


def _load() -> dict:
    if HOSTS_FILE.exists():
        with open(HOSTS_FILE) as f:
            return json.load(f)
    return {}


def _save(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    HOSTS_FILE.chmod(0o700) if HOSTS_FILE.exists() else None
    with open(HOSTS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(HOSTS_FILE, 0o600)


def save_host(alias: str, host: str, username: str, password: str = "", port: int = 22):
    data = _load()
    data[alias] = {"host": host, "username": username, "password": password, "port": port}
    _save(data)
    console.print(f"[green]Saved host '[bold]{alias}[/bold]' → {username}@{host}:{port}[/green]")


def get_host(alias: str) -> dict | None:
    return _load().get(alias)


def delete_host(alias: str):
    data = _load()
    if alias in data:
        del data[alias]
        _save(data)
        console.print(f"[yellow]Removed '[bold]{alias}[/bold]'[/yellow]")
    else:
        console.print(f"[red]No host named '{alias}'[/red]")


def list_hosts():
    data = _load()
    if not data:
        console.print("[dim]No saved hosts.[/dim]")
        return

    table = Table(title="Saved Hosts", border_style="cyan")
    table.add_column("Alias", style="bold cyan")
    table.add_column("Host")
    table.add_column("User")
    table.add_column("Port", justify="right")

    for alias, info in sorted(data.items()):
        table.add_row(alias, info["host"], info["username"], str(info.get("port", 22)))

    console.print(table)


def resolve(alias_or_host: str) -> tuple[str, str, str, int] | None:
    """
    Resolve an alias or raw host. Returns (host, username, password, port) or None.
    """
    data = _load()
    if alias_or_host in data:
        e = data[alias_or_host]
        return e["host"], e["username"], e.get("password", ""), e.get("port", 22)
    return None
