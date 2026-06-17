"""
TLS certificate expiry checking.
"""
import socket
import ssl
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

console = Console()


def check_cert(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    result = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                result["san"] = [v for _, v in cert.get("subjectAltName", ())]
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    result["expires"] = expiry.isoformat()
                    result["days_left"] = days_left
                    result["ok"] = days_left > 0
                else:
                    result["ok"] = False
                    result["error"] = "no expiry date in cert"
    except ssl.SSLCertVerificationError as e:
        result["ok"] = False
        result["error"] = f"verification failed: {e}"
        result["days_left"] = None
    except Exception as e:
        result["ok"] = False
        result["error"] = str(e)[:100]
        result["days_left"] = None
    return result


def check_certs(host: str, ports: list[int] = None) -> list[dict]:
    ports = ports or [443]
    return [check_cert(host, p) for p in ports]


def print_cert_results(host: str, results: list[dict]):
    table = Table(title=f"Certificate Expiry — {host}", border_style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Subject")
    table.add_column("Expires")
    table.add_column("Days Left", justify="right")
    table.add_column("Status")

    for r in results:
        port = str(r["port"])
        subject = r.get("subject", {}).get("commonName", r.get("error", "—"))
        expires = r.get("expires", "—")[:10] if r.get("expires") else "—"
        days = r.get("days_left")
        if days is None:
            days_str = "—"
            status = f"[red]ERR[/red]"
        elif days < 0:
            days_str = str(days)
            status = "[bold red]EXPIRED[/bold red]"
        elif days < 14:
            days_str = str(days)
            status = "[yellow]WARNING[/yellow]"
        elif days < 30:
            days_str = str(days)
            status = "[yellow]SOON[/yellow]"
        else:
            days_str = str(days)
            status = "[green]OK[/green]"
        table.add_row(port, str(subject), expires, days_str, status)

    console.print(table)
