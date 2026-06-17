"""
Remote vulnerability and security posture checks.
"""
from rich.console import Console
from rich.table import Table
from .ssh import SSHClient

console = Console()

CHECKS = [
    ("upgradable_packages", "Upgradable packages", "apt list --upgradable 2>/dev/null | grep -c upgradable || yum check-update -q 2>/dev/null | wc -l"),
    ("root_login", "SSH PermitRootLogin", "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'not found'"),
    ("password_auth", "SSH PasswordAuthentication", "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'not found'"),
    ("empty_passwords", "Empty password accounts", "awk -F: '($2==\"\" || $2==\"!\"){print $1}' /etc/shadow 2>/dev/null | wc -l"),
    ("world_writable", "World-writable files in /tmp", "find /tmp -maxdepth 2 -type f -perm -002 2>/dev/null | wc -l"),
    ("suid_binaries", "SUID binaries", "find / -perm -4000 -type f 2>/dev/null | wc -l"),
    ("listening_ports", "Listening ports", "ss -tlnp 2>/dev/null | tail -n +2 | wc -l"),
    ("ufw_status", "Firewall status", "ufw status 2>/dev/null | head -1 || iptables -L -n 2>/dev/null | head -3 || echo 'no firewall detected'"),
    ("kernel_version", "Kernel version", "uname -r"),
    ("last_logins", "Failed login attempts (24h)", "journalctl --since '24 hours ago' -u ssh -u sshd 2>/dev/null | grep -ci 'failed\\|invalid' || lastb 2>/dev/null | wc -l"),
]


def _assess(name: str, raw: str) -> tuple[str, str]:
    """Return (severity, detail) for a check result."""
    raw = raw.strip()
    if name == "upgradable_packages":
        count = int(raw) if raw.isdigit() else 0
        if count > 50:
            return "high", f"{count} packages need updates"
        if count > 10:
            return "medium", f"{count} packages need updates"
        return "low", f"{count} packages need updates"

    if name == "root_login":
        if "yes" in raw.lower():
            return "high", raw
        return "low", raw

    if name == "password_auth":
        if "yes" in raw.lower():
            return "medium", raw
        return "low", raw

    if name == "empty_passwords":
        count = int(raw) if raw.isdigit() else 0
        if count > 0:
            return "critical", f"{count} accounts with empty passwords"
        return "low", "none found"

    if name == "world_writable":
        count = int(raw) if raw.isdigit() else 0
        if count > 20:
            return "medium", f"{count} world-writable files"
        return "low", f"{count} found"

    if name == "suid_binaries":
        count = int(raw) if raw.isdigit() else 0
        if count > 30:
            return "medium", f"{count} SUID binaries"
        return "low", f"{count} found"

    if name == "last_logins":
        count = int(raw) if raw.isdigit() else 0
        if count > 100:
            return "high", f"{count} failed attempts"
        if count > 20:
            return "medium", f"{count} failed attempts"
        return "low", f"{count} failed attempts"

    return "info", raw[:80]


def run_vuln_checks(host: str, username: str, password: str) -> list[dict]:
    results = []
    with SSHClient(host, username, password) as ssh:
        for key, label, cmd in CHECKS:
            raw = ssh.run_out(cmd, timeout=60)
            severity, detail = _assess(key, raw)
            results.append({
                "check": label,
                "severity": severity,
                "detail": detail,
                "raw": raw[:200],
            })
    return results


def print_vuln_results(host: str, results: list[dict]):
    sev_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }

    table = Table(title=f"Security Posture — {host}", border_style="yellow")
    table.add_column("Check", style="bold")
    table.add_column("Severity")
    table.add_column("Detail")

    for r in results:
        color = sev_colors.get(r["severity"], "white")
        table.add_row(r["check"], f"[{color}]{r['severity']}[/{color}]", r["detail"])

    console.print(table)

    critical = sum(1 for r in results if r["severity"] in ("critical", "high"))
    if critical:
        console.print(f"\n[red]⚠ {critical} critical/high findings[/red]")
    else:
        console.print(f"\n[green]No critical/high findings[/green]")
