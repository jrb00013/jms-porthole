"""
Remote process and service management.
"""
from rich.console import Console
from rich.table import Table
from .ssh import SSHClient

console = Console()


def list_services(host: str, username: str, password: str,
                  filter_state: str = None) -> list[dict]:
    with SSHClient(host, username, password) as ssh:
        raw = ssh.run_out(
            "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null "
            "| awk '{print $1, $3, $4}'"
        )

    services = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, state = parts[0], parts[1]
        if filter_state and state != filter_state:
            continue
        services.append({"name": name, "state": state, "description": " ".join(parts[2:])})
    return services


def list_processes(host: str, username: str, password: str,
                   sort_by: str = "cpu", limit: int = 20) -> list[dict]:
    sort_col = {"cpu": 3, "mem": 4, "pid": 1}.get(sort_by, 3)
    with SSHClient(host, username, password) as ssh:
        raw = ssh.run_out(
            f"ps aux --sort=-{sort_col} | awk 'NR>1 && NR<={limit + 1}'"
            " '{printf \"%s|%s|%s|%s|%s\\n\", $1, $2, $3, $4, $11}'"
        )

    procs = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) >= 5:
            procs.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu": parts[2],
                "mem": parts[3],
                "command": parts[4],
            })
    return procs


def service_action(host: str, username: str, password: str,
                   service: str, action: str) -> tuple[bool, str]:
    allowed = {"start", "stop", "restart", "status", "enable", "disable"}
    if action not in allowed:
        raise ValueError(f"Unknown action: {action}")

    with SSHClient(host, username, password) as ssh:
        out, err, code = ssh.run_sudo(f"systemctl {action} {service}")

    ok = code == 0
    msg = out or err
    return ok, msg


def kill_process(host: str, username: str, password: str,
                 pid: int, signal: str = "TERM") -> tuple[bool, str]:
    with SSHClient(host, username, password) as ssh:
        out, err, code = ssh.run(f"kill -{signal} {pid}")
    return code == 0, out or err


def print_services(host: str, services: list[dict]):
    table = Table(title=f"Services — {host}", border_style="cyan")
    table.add_column("Service", style="bold")
    table.add_column("State")
    table.add_column("Description", style="dim")

    state_colors = {"active": "green", "failed": "red", "inactive": "dim"}
    for s in services:
        color = state_colors.get(s["state"], "white")
        table.add_row(s["name"], f"[{color}]{s['state']}[/{color}]", s.get("description", ""))
    console.print(table)


def print_processes(host: str, procs: list[dict]):
    table = Table(title=f"Processes — {host}", border_style="cyan")
    table.add_column("PID", justify="right")
    table.add_column("User")
    table.add_column("CPU%", justify="right")
    table.add_column("MEM%", justify="right")
    table.add_column("Command")

    for p in procs:
        table.add_row(p["pid"], p["user"], p["cpu"], p["mem"], p["command"][:50])
    console.print(table)
