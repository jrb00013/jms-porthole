"""
DNS enumeration — record lookups and subdomain discovery.
"""
import socket
import subprocess
import shutil
from rich.console import Console
from rich.table import Table

console = Console()

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "ns1", "ns2", "mx", "smtp", "webmail", "portal", "cdn",
    "blog", "shop", "app", "dashboard", "git", "jenkins", "grafana",
]


def _dig(domain: str, rtype: str = "ANY") -> str:
    if shutil.which("dig"):
        try:
            result = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    if shutil.which("host"):
        try:
            result = subprocess.run(
                ["host", "-t", rtype, domain],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return ""


def lookup_a(domain: str) -> list[str]:
    try:
        return list({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        return []


def lookup_aaaa(domain: str) -> list[str]:
    try:
        return list({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except socket.gaierror:
        return []


def lookup_records(domain: str, rtypes: list[str] = None) -> dict:
    rtypes = rtypes or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}

    if "A" in rtypes:
        results["A"] = lookup_a(domain)
    if "AAAA" in rtypes:
        results["AAAA"] = lookup_aaaa(domain)

    for rtype in rtypes:
        if rtype in ("A", "AAAA"):
            continue
        raw = _dig(domain, rtype)
        if raw:
            results[rtype] = [l for l in raw.splitlines() if l.strip()]

    return results


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def enumerate_subdomains(domain: str, wordlist: list[str] = None) -> list[dict]:
    wordlist = wordlist or COMMON_SUBDOMAINS
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        ips = lookup_a(fqdn)
        if ips:
            found.append({"subdomain": fqdn, "ips": ips})
    return found


def print_dns_results(domain: str, records: dict):
    table = Table(title=f"DNS Records — {domain}", border_style="cyan")
    table.add_column("Type", style="bold cyan")
    table.add_column("Value")

    for rtype, values in records.items():
        if not values:
            table.add_row(rtype, "[dim]—[/dim]")
        else:
            for i, v in enumerate(values):
                table.add_row(rtype if i == 0 else "", v)
    console.print(table)


def print_subdomain_results(domain: str, found: list[dict]):
    if not found:
        console.print(f"[dim]No subdomains found for {domain}[/dim]")
        return

    table = Table(title=f"Subdomains — {domain} ({len(found)} found)", border_style="green")
    table.add_column("Subdomain", style="bold green")
    table.add_column("IP")

    for entry in found:
        table.add_row(entry["subdomain"], ", ".join(entry["ips"]))
    console.print(table)
