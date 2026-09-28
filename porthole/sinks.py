"""
Alerting sinks — fan out a health-check failure notification to one or more
destinations: a generic webhook, Slack (via its incoming-webhook payload
shape), or email (SMTP). Each sink implements the same `Sink` interface so
`alert.py` can hold a list of configured sinks and notify() all of them.
"""

import json
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from typing import Protocol


class Sink(Protocol):
    def notify(
        self, host: str, failures: list[dict]
    ) -> bool: ...  # pragma: no cover - structural typing only


def _generic_payload(host: str, failures: list[dict]) -> dict:
    return {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "status": "failed",
        "failures": failures,
    }


def _slack_payload(host: str, failures: list[dict]) -> dict:
    lines = [f"*{host}* health check failed:"]
    for f in failures:
        lines.append(f"• {f['name']}: {f.get('error', f.get('status', 'down'))}")
    return {"text": "\n".join(lines)}


class WebhookSink:
    """POSTs a generic JSON payload to an arbitrary webhook URL."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def notify(self, host: str, failures: list[dict]) -> bool:
        return _post_json(self.url, _generic_payload(host, failures), self.timeout)


class SlackSink:
    """POSTs a Slack-shaped `{"text": ...}` payload to a Slack incoming webhook URL."""

    name = "slack"

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def notify(self, host: str, failures: list[dict]) -> bool:
        return _post_json(self.url, _slack_payload(host, failures), self.timeout)


class EmailSink:
    """Sends a plaintext email alert over SMTP."""

    name = "email"

    def __init__(
        self,
        smtp_host: str,
        from_addr: str,
        to_addr: str,
        smtp_port: int = 587,
        username: str = None,
        password: str = None,
        use_tls: bool = True,
        timeout: float = 10.0,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

    def _build_message(self, host: str, failures: list[dict]) -> MIMEText:
        lines = [f"{host} health check failed at {datetime.now().isoformat()}:", ""]
        for f in failures:
            lines.append(f"  - {f['name']}: {f.get('error', f.get('status', 'down'))}")
        msg = MIMEText("\n".join(lines))
        msg["Subject"] = f"[porthole] {host} health check failure ({len(failures)} check(s))"
        msg["From"] = self.from_addr
        msg["To"] = self.to_addr
        return msg

    def notify(self, host: str, failures: list[dict]) -> bool:
        msg = self._build_message(host, failures)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, [self.to_addr], msg.as_string())
            return True
        except Exception:
            return False


def _post_json(url: str, payload: dict, timeout: float) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


def notify_all(sinks: list[Sink], host: str, failures: list[dict]) -> dict[str, bool]:
    """Fan out one failure notification to every configured sink."""
    return {sink.name: sink.notify(host, failures) for sink in sinks}
