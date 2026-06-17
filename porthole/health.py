"""
Remote health checks — verify services are responding correctly.
"""
import socket
import time
import http.client
from rich.console import Console
from rich.table import Table

console = Console()

CHECK_TIMEOUT = 3.0


def check_http(host: str, port: int = 80, path: str = "/", https: bool = False) -> dict:
    status, latency, body = None, None, ""
    try:
        start = time.monotonic()
        if https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=CHECK_TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=CHECK_TIMEOUT)
        conn.request("GET", path, headers={"Host": host})
        resp = conn.getresponse()
        latency = round((time.monotonic() - start) * 1000, 1)
        status = resp.status
        body = resp.read(200).decode(errors="replace")
        conn.close()
    except Exception as e:
        body = str(e)
    return {"port": port, "status": status, "latency_ms": latency, "snippet": body[:80]}


def check_tcp(host: str, port: int) -> dict:
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=CHECK_TIMEOUT):
            latency = round((time.monotonic() - start) * 1000, 1)
        return {"port": port, "open": True, "latency_ms": latency}
    except Exception as e:
        return {"port": port, "open": False, "latency_ms": None, "error": str(e)[:60]}


def run_health_checks(host: str, checks: list[dict]) -> list[dict]:
    """
    checks: list of {"type": "http"|"tcp", "port": int, ...}
    """
    results = []
    for c in checks:
        if c["type"] == "http":
            r = check_http(host, c.get("port", 80), c.get("path", "/"), c.get("https", False))
        else:
            r = check_tcp(host, c["port"])
        r.update({"type": c["type"], "name": c.get("name", f"{c['type']}:{c['port']}")})
        results.append(r)
    return results


def print_health_results(host: str, results: list[dict]):
    table = Table(title=f"Health Checks — {host}", border_style="cyan")
    table.add_column("Service", style="bold cyan")
    table.add_column("Status")
    table.add_column("Latency", justify="right")
    table.add_column("Detail", style="dim")

    for r in results:
        if r["type"] == "http":
            code = r.get("status")
            ok = code and 200 <= code < 400
            status_str = f"[green]{code}[/green]" if ok else f"[red]{code or 'ERR'}[/red]"
            detail = r.get("snippet", "")[:60]
        else:
            ok = r.get("open", False)
            status_str = "[green]open[/green]" if ok else "[red]closed[/red]"
            detail = r.get("error", "")

        latency = f"{r['latency_ms']}ms" if r.get("latency_ms") else "—"
        table.add_row(r["name"], status_str, latency, detail)

    console.print(table)
