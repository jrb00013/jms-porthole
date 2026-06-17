"""
Alerting — periodic health checks with webhook notifications on failure.
"""
import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from rich.console import Console
from rich.table import Table
from .health import run_health_checks

console = Console()


def send_webhook(url: str, payload: dict, timeout: float = 10.0) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


def _build_slack_payload(host: str, failures: list[dict]) -> dict:
    lines = [f"*{host}* health check failed:"]
    for f in failures:
        lines.append(f"• {f['name']}: {f.get('error', f.get('status', 'down'))}")
    return {"text": "\n".join(lines)}


def _build_generic_payload(host: str, failures: list[dict]) -> dict:
    return {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "status": "failed",
        "failures": failures,
    }


def run_alert_loop(host: str, checks: list[dict], interval: int = 60,
                   webhook: str = None, slack: bool = False,
                   max_iterations: int = None):
    """Run health checks on interval. Alert via webhook on any failure."""
    iteration = 0
    last_alert_time = 0
    alert_cooldown = interval

    console.print(f"[cyan]Monitoring {host} every {interval}s[/cyan]")
    if webhook:
        console.print(f"[dim]Webhook: {webhook}[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        while max_iterations is None or iteration < max_iterations:
            results = run_health_checks(host, checks)
            failures = []
            now = time.time()

            for r in results:
                if r["type"] == "http":
                    ok = r.get("status") and 200 <= r["status"] < 400
                else:
                    ok = r.get("open", False)
                if not ok:
                    failures.append(r)

            table = Table(title=f"Alert Monitor — {host} ({datetime.now().strftime('%H:%M:%S')})")
            table.add_column("Service")
            table.add_column("Status")
            table.add_column("Latency", justify="right")

            for r in results:
                if r["type"] == "http":
                    ok = r.get("status") and 200 <= r["status"] < 400
                    status = f"[green]{r['status']}[/green]" if ok else f"[red]{r.get('status', 'ERR')}[/red]"
                else:
                    ok = r.get("open", False)
                    status = "[green]open[/green]" if ok else "[red]closed[/red]"
                latency = f"{r.get('latency_ms', '—')}ms"
                table.add_row(r["name"], status, latency)

            console.clear()
            console.print(table)

            if failures and webhook and (now - last_alert_time) >= alert_cooldown:
                payload = _build_slack_payload(host, failures) if slack else _build_generic_payload(host, failures)
                if send_webhook(webhook, payload):
                    console.print(f"[yellow]⚠ Alert sent for {len(failures)} failure(s)[/yellow]")
                    last_alert_time = now
                else:
                    console.print("[red]Failed to send webhook alert[/red]")
            elif failures:
                console.print(f"[yellow]⚠ {len(failures)} check(s) failing[/yellow]")

            iteration += 1
            if max_iterations is None or iteration < max_iterations:
                time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Alert monitor stopped.[/yellow]")
