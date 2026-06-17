from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .ssh import SSHClient

console = Console()


def collect_sysinfo(ssh: SSHClient) -> dict:
    info = {}

    cmds = {
        "hostname":     "hostname -f",
        "os":           "lsb_release -d 2>/dev/null | cut -d: -f2 | xargs || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'",
        "kernel":       "uname -r",
        "arch":         "uname -m",
        "cpu_model":    "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs",
        "cpu_cores":    "nproc",
        "ram_total":    "free -h | awk '/^Mem:/{print $2}'",
        "disk_total":   "df -h --total | tail -1 | awk '{print $2}'",
        "ip_addrs":     "ip -4 addr show | grep inet | awk '{print $2}' | tr '\\n' ' '",
        "mac_addrs":    "ip link show | awk '/link\\/ether/{print $2}' | tr '\\n' ' '",
        "default_gw":   "ip route | grep default | awk '{print $3}' | head -1",
        "dns":          "cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | tr '\\n' ' '",
        "users":        "cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1 | tr '\\n' ' '",
        "sudo_users":   "cat /etc/sudoers 2>/dev/null | grep -v '#' | grep ALL | head -10",
        "open_ports":   "ss -tlnp | awk 'NR>1{print $4}' | grep -oP ':\\K\\d+' | sort -n | tr '\\n' ' '",
        "running_svcs": "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | tr '\\n' ' '",
        "last_logins":  "last | head -5 | awk '{print $1, $3, $4, $5, $6, $7}' | head -5",
        "cron_jobs":    "crontab -l 2>/dev/null | grep -v '#' | head -10",
        "env_vars":     "env | grep -E '(PATH|HOME|USER|SHELL|LANG)' | head -10",
        "installed_pkgs": "dpkg -l 2>/dev/null | grep '^ii' | wc -l || rpm -qa 2>/dev/null | wc -l",
        "docker":       "docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | head -5 || echo 'not running'",
        "uptime":       "uptime -p",
    }

    for key, cmd in cmds.items():
        info[key] = ssh.run_out(cmd)

    return info


def print_sysinfo(host: str, info: dict):
    def section(title: str, rows: list[tuple[str, str]]):
        t = Table(title=f"[bold]{title}[/bold]", border_style="cyan", expand=True, show_header=False)
        t.add_column("Key", style="bold cyan", width=18)
        t.add_column("Value")
        for k, v in rows:
            t.add_row(k, v or "[dim]—[/dim]")
        console.print(t)

    console.print(Panel(f"[bold cyan]{info.get('hostname', host)}[/bold cyan]  ·  {info.get('os', '?')}",
                        title="[bold]🖥  System Info[/bold]", border_style="bright_cyan"))

    section("Hardware", [
        ("CPU", info.get("cpu_model", "?")),
        ("Cores", info.get("cpu_cores", "?")),
        ("RAM", info.get("ram_total", "?")),
        ("Disk total", info.get("disk_total", "?")),
        ("Arch", info.get("arch", "?")),
        ("Kernel", info.get("kernel", "?")),
    ])

    section("Network", [
        ("IP addresses", info.get("ip_addrs", "?")),
        ("MAC addresses", info.get("mac_addrs", "?")),
        ("Default gateway", info.get("default_gw", "?")),
        ("DNS", info.get("dns", "?")),
        ("Open ports", info.get("open_ports", "?")),
    ])

    section("Access", [
        ("Local users", info.get("users", "?")),
        ("Sudo rules", info.get("sudo_users", "?")),
        ("Last logins", info.get("last_logins", "?")),
    ])

    section("Services & Runtime", [
        ("Running services", info.get("running_svcs", "?")[:120]),
        ("Installed pkgs", info.get("installed_pkgs", "?")),
        ("Docker containers", info.get("docker", "?")),
        ("Uptime", info.get("uptime", "?")),
    ])

    if info.get("cron_jobs"):
        section("Cron Jobs", [("", line) for line in info["cron_jobs"].splitlines()])
