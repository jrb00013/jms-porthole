"""
Alerting — periodic health checks with pluggable notification sinks
(webhook, Slack, email — see sinks.py) on failure.
"""
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from .health import run_health_checks
from .sinks import Sink, WebhookSink, SlackSink, notify_all

console = Console()


def send_webhook(url: str, payload: dict, timeout: float = 10.0) -> bool:
    """Kept for backward compatibility — prefer sinks.WebhookSink/notify_all."""
    from .sinks import _post_json
    return _post_json(url, payload, timeout)


def build_sinks(webhook: str = None, slack: bool = False, extra_webhooks: list[str] = None,
                 sinks: list[Sink] = None) -> list[Sink]:
    """
    Build the sink list for an alert run from CLI-friendly convenience args
    plus any pre-built Sink objects (e.g. an EmailSink) the caller supplies.
    """
    built: list[Sink] = list(sinks or [])
    if webhook:
        built.append(SlackSink(webhook) if slack else WebhookSink(webhook))
    for url in (extra_webhooks or []):
        built.append(WebhookSink(url))
    return built


def run_alert_loop(host: str, checks: list[dict], interval: int = 60,
                   webhook: str = None, slack: bool = False,
                   max_iterations: int = None, sinks: list[Sink] = None,
                   extra_webhooks: list[str] = None):
    """Run health checks on interval. Notify every configured sink on failure."""
    iteration = 0
    last_alert_time = 0
    alert_cooldown = interval

    active_sinks = build_sinks(webhook=webhook, slack=slack, extra_webhooks=extra_webhooks, sinks=sinks)

    console.print(f"[cyan]Monitoring {host} every {interval}s[/cyan]")
    if active_sinks:
        console.print(f"[dim]Sinks: {', '.join(s.name for s in active_sinks)}[/dim]")
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

            if failures and active_sinks and (now - last_alert_time) >= alert_cooldown:
                outcomes = notify_all(active_sinks, host, failures)
                ok = [name for name, sent in outcomes.items() if sent]
                failed = [name for name, sent in outcomes.items() if not sent]
                if ok:
                    console.print(f"[yellow]⚠ Alert sent for {len(failures)} failure(s) via {', '.join(ok)}[/yellow]")
                    last_alert_time = now
                if failed:
                    console.print(f"[red]Failed to notify: {', '.join(failed)}[/red]")
            elif failures:
                console.print(f"[yellow]⚠ {len(failures)} check(s) failing[/yellow]")

            iteration += 1
            if max_iterations is None or iteration < max_iterations:
                time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Alert monitor stopped.[/yellow]")
