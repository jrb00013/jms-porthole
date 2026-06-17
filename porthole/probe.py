"""
Service probing — banner grabbing and fingerprinting for common ports.
"""
import socket
import ssl
import re
from rich.console import Console
from rich.table import Table

console = Console()

SERVICE_PROBES = {
    22:   ("SSH",        b""),
    21:   ("FTP",        b""),
    25:   ("SMTP",       b"EHLO jms\r\n"),
    80:   ("HTTP",       b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    110:  ("POP3",       b""),
    143:  ("IMAP",       b""),
    443:  ("HTTPS",      b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    3306: ("MySQL",      b""),
    5432: ("PostgreSQL", b""),
    6379: ("Redis",      b"PING\r\n"),
    27017:("MongoDB",    b""),
    5900: ("VNC",        b""),
    5901: ("VNC",        b""),
    3389: ("RDP",        b""),
}

VERSION_PATTERNS = [
    (r"SSH-(\S+)", "SSH"),
    (r"220[- ](\S+.*)", "FTP/SMTP"),
    (r"Server: ([^\r\n]+)", "HTTP Server"),
    (r"X-Powered-By: ([^\r\n]+)", "Powered-By"),
    (r"OpenSSH[_/](\S+)", "OpenSSH"),
    (r"nginx[/](\S+)", "nginx"),
    (r"Apache[/](\S+)", "Apache"),
    (r"\+PONG", "Redis"),
    (r"5\.(\d+\.\d+)", "MySQL"),
]


def probe_service(host: str, port: int, timeout: float = 3.0) -> dict:
    result = {"port": port, "open": False, "service": "", "banner": "", "version": ""}

    service_hint, probe_data = SERVICE_PROBES.get(port, ("unknown", b""))
    result["service"] = service_hint

    try:
        use_ssl = port == 443
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=host)
        else:
            conn = socket.create_connection((host, port), timeout=timeout)

        result["open"] = True
        conn.settimeout(timeout)

        if probe_data:
            conn.sendall(probe_data)

        try:
            banner = conn.recv(1024).decode(errors="replace").strip()[:200]
            result["banner"] = banner

            for pattern, label in VERSION_PATTERNS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    result["version"] = m.group(1) if m.lastindex else label
                    break
        except Exception:
            pass

        conn.close()

        if use_ssl:
            try:
                raw2 = socket.create_connection((host, port), timeout=timeout)
                conn2 = ctx.wrap_socket(raw2, server_hostname=host)
                cert = conn2.getpeercert(binary_form=False) or {}
                subject = dict(x[0] for x in cert.get("subject", []))
                result["tls_cn"] = subject.get("commonName", "")
                result["tls_expiry"] = cert.get("notAfter", "")
                conn2.close()
            except Exception:
                pass

    except (ConnectionRefusedError, socket.timeout, OSError):
        pass

    return result


def probe_host(host: str, ports: list[int] = None) -> list[dict]:
    if ports is None:
        ports = list(SERVICE_PROBES.keys())

    results = []
    for port in sorted(ports):
        r = probe_service(host, port)
        if r["open"]:
            results.append(r)
    return results


def print_probe_results(host: str, results: list[dict]):
    if not results:
        console.print(f"[yellow]No open services found on {host}[/yellow]")
        return

    table = Table(title=f"Service Probe — {host}", border_style="cyan")
    table.add_column("Port", style="bold cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Version")
    table.add_column("Banner", style="dim")

    for r in results:
        table.add_row(
            str(r["port"]),
            r["service"],
            r.get("version", ""),
            r["banner"][:80] if r["banner"] else "",
        )

    console.print(table)
