import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5901: "VNC-1", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(1024).decode(errors="replace").strip()[:80]
            except Exception:
                return ""
    except Exception:
        return ""


def ping_host(host: str, timeout: float = 1.0) -> bool:
    return check_port(host, 22, timeout) or check_port(host, 80, timeout) or check_port(host, 443, timeout)


def scan_ports(host: str, ports: list[int] = None, threads: int = 100) -> dict[int, str]:
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_port, host, p): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                banner = grab_banner(host, port)
                service = COMMON_PORTS.get(port, "unknown")
                open_ports[port] = f"{service}  {banner}".strip()
    return dict(sorted(open_ports.items()))


def scan_network(cidr: str, threads: int = 50) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {e}")

    hosts = [str(ip) for ip in network.hosts()]
    live = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task(f"Scanning {cidr} ({len(hosts)} hosts)...", total=len(hosts))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(ping_host, h): h for h in hosts}
            for future in as_completed(futures):
                progress.advance(task)
                if future.result():
                    live.append(futures[future])

    return sorted(live)


def print_scan_results(host: str, open_ports: dict[int, str]):
    if not open_ports:
        console.print(f"[yellow]No open ports found on {host}[/yellow]")
        return

    table = Table(title=f"Open Ports — {host}", border_style="cyan")
    table.add_column("Port", style="bold cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="dim")

    for port, info in open_ports.items():
        parts = info.split("  ", 1)
        service = parts[0]
        banner = parts[1] if len(parts) > 1 else ""
        table.add_row(str(port), service, banner)

    console.print(table)


def print_network_results(cidr: str, live_hosts: list[str]):
    table = Table(title=f"Live Hosts — {cidr}", border_style="green")
    table.add_column("IP Address", style="bold green")
    table.add_column("Status", style="cyan")

    for h in live_hosts:
        table.add_row(h, "● online")

    console.print(table)
    console.print(f"[bold]{len(live_hosts)} host(s) online[/bold]")
