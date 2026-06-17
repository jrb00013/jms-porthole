"""
Network mapping — ARP scan for local subnet, traceroute, and reverse DNS.
"""
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table

console = Console()


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def ping_icmp(host: str) -> bool:
    """Use system ping to check if host is alive."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", host],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def map_network(cidr: str, resolve_dns: bool = True, threads: int = 50) -> list[dict]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {e}")

    hosts = [str(ip) for ip in network.hosts()]
    results = []

    def probe(ip):
        alive = ping_icmp(ip)
        if not alive:
            # fallback: try common TCP ports
            for port in [22, 80, 443]:
                try:
                    with socket.create_connection((ip, port), timeout=0.5):
                        alive = True
                        break
                except Exception:
                    pass
        if alive:
            hostname = reverse_dns(ip) if resolve_dns else ""
            return {"ip": ip, "hostname": hostname}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, h): h for h in hosts}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r)

    return sorted(results, key=lambda x: [int(p) for p in x["ip"].split(".")])


def traceroute(host: str, max_hops: int = 20) -> list[dict]:
    hops = []
    for ttl in range(1, max_hops + 1):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            recv_sock.settimeout(1)

            recv_sock.bind(("", 33434))
            send_sock.sendto(b"", (host, 33434))

            hop_ip = ""
            try:
                _, addr = recv_sock.recvfrom(512)
                hop_ip = addr[0]
            except socket.timeout:
                hop_ip = "*"

            hostname = ""
            if hop_ip != "*":
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    pass

            hops.append({"ttl": ttl, "ip": hop_ip, "hostname": hostname})

            send_sock.close()
            recv_sock.close()

            if hop_ip == socket.gethostbyname(host):
                break
        except Exception:
            hops.append({"ttl": ttl, "ip": "*", "hostname": ""})

    return hops


def print_map_results(cidr: str, results: list[dict]):
    table = Table(title=f"Network Map — {cidr}", border_style="cyan")
    table.add_column("IP", style="bold cyan")
    table.add_column("Hostname", style="dim")

    for r in results:
        table.add_row(r["ip"], r.get("hostname", ""))

    console.print(table)
    console.print(f"[bold]{len(results)} host(s) found[/bold]")


def print_traceroute(host: str, hops: list[dict]):
    table = Table(title=f"Traceroute — {host}", border_style="cyan")
    table.add_column("Hop", justify="right", style="bold cyan")
    table.add_column("IP")
    table.add_column("Hostname", style="dim")

    for h in hops:
        table.add_row(str(h["ttl"]), h["ip"], h.get("hostname", ""))

    console.print(table)
