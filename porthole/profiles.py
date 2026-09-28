"""
Config profiles — named host groups with default ports, credentials,
timeouts, and an optional jump-host, stored as YAML under
~/.porthole/profiles/*.yaml.

Distinct from porthole/config.py's single-host aliases: a profile describes
a *group* of hosts sharing settings (e.g. "prod-web": hosts=[...],
default ports=[80,443], username=deploy, jump_host=bastion.example.com).
"""

from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.table import Table

console = Console()

PROFILES_DIR = Path.home() / ".porthole" / "profiles"

DEFAULT_PROFILE = {
    "hosts": [],
    "username": None,
    "ports": [],
    "timeout": 10,
    "jump_host": None,
}


def _profile_path(name: str) -> Path:
    return PROFILES_DIR / f"{name}.yaml"


def save_profile(
    name: str,
    hosts: list[str],
    username: str = None,
    ports: list[int] = None,
    timeout: int = 10,
    jump_host: str = None,
) -> Path:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "hosts": hosts,
        "username": username,
        "ports": ports or [],
        "timeout": timeout,
        "jump_host": jump_host,
    }
    path = _profile_path(name)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    path.chmod(0o600)
    return path


def load_profile(name: str) -> Optional[dict]:
    path = _profile_path(name)
    if not path.exists():
        return None
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    merged = dict(DEFAULT_PROFILE)
    merged.update(data)
    return merged


def delete_profile(name: str) -> bool:
    path = _profile_path(name)
    if path.exists():
        path.unlink()
        return True
    return False


def list_profiles() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


def print_profiles():
    names = list_profiles()
    if not names:
        console.print("[dim]No profiles saved.[/dim]")
        return

    table = Table(title="Profiles", border_style="cyan")
    table.add_column("Name", style="bold cyan")
    table.add_column("Hosts")
    table.add_column("User")
    table.add_column("Ports")
    table.add_column("Jump host")

    for name in names:
        p = load_profile(name)
        table.add_row(
            name,
            ", ".join(p["hosts"]) or "[dim]—[/dim]",
            p.get("username") or "[dim]—[/dim]",
            ", ".join(str(x) for x in p.get("ports", [])) or "[dim]—[/dim]",
            p.get("jump_host") or "[dim]—[/dim]",
        )
    console.print(table)


def print_profile(name: str):
    p = load_profile(name)
    if not p:
        console.print(f"[red]No profile named '{name}'[/red]")
        return
    console.print(f"[bold cyan]{name}[/bold cyan]")
    console.print(f"  hosts:     {', '.join(p['hosts']) or '—'}")
    console.print(f"  username:  {p.get('username') or '—'}")
    console.print(f"  ports:     {', '.join(str(x) for x in p.get('ports', [])) or '—'}")
    console.print(f"  timeout:   {p.get('timeout')}")
    console.print(f"  jump_host: {p.get('jump_host') or '—'}")
