"""Extra unit tests for porthole.alert — loop timing, notification and payload paths.

Complements tests/test_alert.py (sink construction). No network, no real sleeps.
"""

import pytest

from porthole import alert
from porthole.sinks import WebhookSink


class RecordingConsole:
    def __init__(self):
        self.printed = []
        self.cleared = 0

    def print(self, *args, **kwargs):
        self.printed.append(args[0] if args else None)

    def clear(self):
        self.cleared += 1

    def lines(self):
        # Strip Rich markup tags so assertions can match the human-readable text.
        import re

        tag = re.compile(r"\[/?[^\]]+\]")
        return [tag.sub("", p) for p in self.printed if isinstance(p, str)]

    def tables(self):
        return [p for p in self.printed if hasattr(p, "row_count")]


class FakeSink:
    def __init__(self, name, sent=True, raises=False):
        self.name = name
        self.sent = sent
        self.raises = raises
        self.calls = []

    def notify(self, host, failures):
        self.calls.append((host, list(failures)))
        if self.raises:
            raise RuntimeError("smtp down")
        return self.sent


HTTP_OK = {"type": "http", "name": "http:80", "status": 200, "latency_ms": 12.0}
HTTP_REDIRECT = {"type": "http", "name": "http:443", "status": 302, "latency_ms": 8.0}
HTTP_FAIL = {"type": "http", "name": "http:8080", "status": 500, "latency_ms": 30.0}
HTTP_ERROR = {
    "type": "http",
    "name": "http:8081",
    "status": None,
    "latency_ms": None,
    "error": "refused",
}
TCP_OPEN = {"type": "tcp", "name": "tcp:22", "open": True, "latency_ms": 2.0}
TCP_CLOSED = {
    "type": "tcp",
    "name": "tcp:443",
    "open": False,
    "latency_ms": None,
    "error": "closed",
}


@pytest.fixture
def loop_env(monkeypatch):
    """Patch the health checks, the clock, the sinks fan-out and the console."""
    console = RecordingConsole()
    sleeps = []
    health = []
    notified = []

    def fake_health(host, checks):
        if isinstance(health, list) and health and callable(health[0]):
            return health[0](host, checks)
        return list(health)

    def fake_notify_all(sinks, host, failures):
        notified.append((list(sinks), host, list(failures)))
        return {s.name: s.notify(host, failures) for s in sinks}

    monkeypatch.setattr(alert, "console", console)
    monkeypatch.setattr(alert, "run_health_checks", fake_health)
    monkeypatch.setattr(alert, "notify_all", fake_notify_all)
    monkeypatch.setattr(alert.time, "sleep", lambda s: sleeps.append(s))
    return {"console": console, "sleeps": sleeps, "health": health, "notified": notified}


def set_health(env, results):
    # Mutate the fixture list in place — fake_health closes over it by identity.
    env["health"][:] = list(results)


# --------------------------------------------------------------------------
# payload construction / send_webhook()
# --------------------------------------------------------------------------


def test_send_webhook_delegates_to_the_shared_post_json_helper(monkeypatch):
    seen = []

    def fake_post_json(url, payload, timeout):
        seen.append((url, payload, timeout))
        return True

    monkeypatch.setattr("porthole.sinks._post_json", fake_post_json)
    assert alert.send_webhook("https://example.com/hook", {"a": 1}, timeout=3.0) is True
    assert seen == [("https://example.com/hook", {"a": 1}, 3.0)]


def test_send_webhook_returns_false_when_the_post_fails(monkeypatch):
    monkeypatch.setattr("porthole.sinks._post_json", lambda *a: False)
    assert alert.send_webhook("https://example.com/hook", {}) is False


def test_send_webhook_uses_the_default_timeout(monkeypatch):
    seen = []
    monkeypatch.setattr("porthole.sinks._post_json", lambda u, p, t: seen.append(t) or True)
    alert.send_webhook("https://example.com/hook", {})
    assert seen == [10.0]


def test_generic_sink_payload_carries_host_timestamp_and_failures(monkeypatch):
    monkeypatch.setattr("porthole.sinks._post_json", lambda u, p, t: True)
    seen = {}
    import porthole.sinks as sinks

    def capture(url, payload, timeout):
        seen.update(payload)
        return True

    monkeypatch.setattr(sinks, "_post_json", capture)
    WebhookSink("https://example.com/hook").notify("h1", [HTTP_FAIL])
    assert seen["host"] == "h1"
    assert seen["status"] == "failed"
    assert seen["failures"] == [HTTP_FAIL]
    assert seen["timestamp"]


def test_slack_sink_payload_is_a_text_block_listing_each_failure(monkeypatch):
    import porthole.sinks as sinks

    seen = {}
    monkeypatch.setattr(sinks, "_post_json", lambda u, p, t: seen.update(p) or True)
    sinks.SlackSink("https://hooks.slack.com/x").notify("h1", [HTTP_FAIL, TCP_CLOSED])
    assert set(seen) == {"text"}
    assert "*h1* health check failed:" in seen["text"]
    assert "• http:8080: 500" in seen["text"]
    assert "• tcp:443: closed" in seen["text"]


# --------------------------------------------------------------------------
# run_alert_loop(): notification behaviour
# --------------------------------------------------------------------------


def test_run_alert_loop_notifies_every_sink_with_the_failing_checks(loop_env):
    set_health(loop_env, [HTTP_OK, HTTP_FAIL])
    sink = FakeSink("webhook", sent=True)
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[sink])
    assert sink.calls == [("h1", [HTTP_FAIL])]


def test_run_alert_loop_passes_the_monitored_host_and_check_specs_to_health_checks(
    loop_env, monkeypatch
):
    seen = []
    monkeypatch.setattr(
        alert, "run_health_checks", lambda host, checks: seen.append((host, checks)) or [HTTP_OK]
    )
    alert.run_alert_loop("web1", [{"type": "tcp", "port": 22}], max_iterations=1)
    assert seen == [("web1", [{"type": "tcp", "port": 22}])]


def test_run_alert_loop_does_not_notify_when_every_check_passes(loop_env):
    set_health(loop_env, [HTTP_OK, HTTP_REDIRECT, TCP_OPEN])
    sink = FakeSink("webhook", sent=True)
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[sink])
    assert sink.calls == []
    assert loop_env["notified"] == []


def test_run_alert_loop_treats_3xx_as_healthy_and_5xx_as_a_failure(loop_env):
    set_health(loop_env, [HTTP_REDIRECT, HTTP_FAIL, HTTP_ERROR])
    sink = FakeSink("webhook")
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[sink])
    assert [f["name"] for f in sink.calls[0][1]] == ["http:8080", "http:8081"]


def test_run_alert_loop_treats_a_closed_tcp_port_as_a_failure(loop_env):
    set_health(loop_env, [TCP_OPEN, TCP_CLOSED])
    sink = FakeSink("webhook")
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[sink])
    assert [f["name"] for f in sink.calls[0][1]] == ["tcp:443"]


def test_run_alert_loop_prints_the_alert_sent_message_with_the_sink_name(loop_env):
    set_health(loop_env, [HTTP_FAIL, TCP_CLOSED])
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[FakeSink("webhook", sent=True)])
    assert "⚠ Alert sent for 2 failure(s) via webhook" in loop_env["console"].lines()


def test_run_alert_loop_reports_a_sink_that_failed_to_notify(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[FakeSink("email", sent=False)])
    assert "Failed to notify: email" in loop_env["console"].lines()


def test_run_alert_loop_reports_partial_delivery_across_two_sinks(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    sinks = [FakeSink("webhook", sent=True), FakeSink("email", sent=False)]
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=sinks)
    lines = loop_env["console"].lines()
    assert "⚠ Alert sent for 1 failure(s) via webhook" in lines
    assert "Failed to notify: email" in lines


def test_run_alert_loop_keeps_running_after_a_sink_fails_to_notify(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    sink = FakeSink("email", sent=False)
    alert.run_alert_loop("h1", [], max_iterations=3, sinks=[sink])
    assert len(sink.calls) == 3  # every iteration retries, the loop is not aborted
    assert loop_env["console"].cleared == 3


def test_run_alert_loop_prints_the_failing_count_when_no_sink_is_configured(loop_env):
    set_health(loop_env, [HTTP_FAIL, TCP_CLOSED])
    alert.run_alert_loop("h1", [], max_iterations=1)
    assert "⚠ 2 check(s) failing" in loop_env["console"].lines()
    assert loop_env["notified"] == []


def test_run_alert_loop_does_not_update_the_cooldown_when_a_sink_fails(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    sink = FakeSink("email", sent=False)
    alert.run_alert_loop("h1", [], max_iterations=2, interval=10, sinks=[sink])
    assert len(sink.calls) == 2


@pytest.mark.xfail(
    strict=True,
    reason="source bug: alert.py:84 calls notify_all() unguarded, so a raising sink aborts the loop",
)
def test_run_alert_loop_survives_a_sink_that_raises(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    alert.run_alert_loop("h1", [], max_iterations=2, sinks=[FakeSink("email", raises=True)])
    assert loop_env["console"].cleared == 2


# --------------------------------------------------------------------------
# run_alert_loop(): timing / interval
# --------------------------------------------------------------------------


def test_run_alert_loop_sleeps_the_configured_interval_between_iterations(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("h1", [], interval=45, max_iterations=4)
    assert loop_env["sleeps"] == [45, 45, 45]


def test_run_alert_loop_does_not_sleep_after_the_final_iteration(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("h1", [], interval=45, max_iterations=1)
    assert loop_env["sleeps"] == []


def test_run_alert_loop_runs_exactly_max_iterations_times(loop_env, monkeypatch):
    runs = []
    monkeypatch.setattr(alert, "run_health_checks", lambda h, c: runs.append(h) or [HTTP_OK])
    alert.run_alert_loop("h1", [], max_iterations=7)
    assert len(runs) == 7


def test_run_alert_loop_re_evaluates_the_checks_on_each_iteration(loop_env, monkeypatch):
    rounds = [[HTTP_OK], [HTTP_FAIL]]

    def step(_host, _checks):
        return rounds.pop(0)

    monkeypatch.setattr(alert, "run_health_checks", step)
    sink = FakeSink("webhook")
    alert.run_alert_loop("h1", [], max_iterations=2, sinks=[sink])
    assert len(sink.calls) == 1
    assert loop_env["console"].cleared == 2


def test_run_alert_loop_suppresses_a_second_alert_inside_the_cooldown_window(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    sink = FakeSink("webhook", sent=True)
    alert.run_alert_loop("h1", [], interval=10_000_000, max_iterations=3, sinks=[sink])
    assert len(sink.calls) == 1  # alert sent once, then muted for `interval` seconds


def test_run_alert_loop_sends_a_fresh_alert_once_the_cooldown_expires(loop_env, monkeypatch):
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(alert.time, "time", lambda: clock["t"])

    def step(_host, _checks):
        clock["t"] += 5000  # each iteration is 5000s apart
        return [HTTP_FAIL]

    monkeypatch.setattr(alert, "run_health_checks", step)
    sink = FakeSink("webhook")
    alert.run_alert_loop("h1", [], interval=100, max_iterations=3, sinks=[sink])
    assert len(sink.calls) == 3


def test_run_alert_loop_swallows_keyboard_interrupt_and_prints_a_stop_message(
    loop_env, monkeypatch
):
    def boom(_host, _checks):
        raise KeyboardInterrupt

    monkeypatch.setattr(alert, "run_health_checks", boom)
    alert.run_alert_loop("h1", [])
    assert "Alert monitor stopped." in loop_env["console"].lines()[-1]
    assert loop_env["sleeps"] == []


def test_run_alert_loop_stops_sleeping_after_keyboard_interrupt(loop_env, monkeypatch):
    calls = {"n": 0}

    def sometimes_raises(_host, _checks):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return [HTTP_OK]

    monkeypatch.setattr(alert, "run_health_checks", sometimes_raises)
    alert.run_alert_loop("h1", [], interval=30)
    assert calls["n"] == 2
    assert loop_env["sleeps"] == [30]  # slept after iteration 1, stopped during iteration 2


# --------------------------------------------------------------------------
# run_alert_loop(): banner and table rendering
# --------------------------------------------------------------------------


def test_run_alert_loop_announces_the_host_and_interval(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("web1", [], interval=30, max_iterations=1)
    assert loop_env["console"].lines()[0] == "Monitoring web1 every 30s"


def test_run_alert_loop_lists_the_configured_sink_names(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("h1", [], max_iterations=1, sinks=[FakeSink("webhook"), FakeSink("email")])
    assert "Sinks: webhook, email" in loop_env["console"].lines()


def test_run_alert_loop_omits_the_sink_line_when_none_are_configured(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("h1", [], max_iterations=1)
    assert not any("Sinks:" in line for line in loop_env["console"].lines())


def test_run_alert_loop_renders_a_status_table_with_one_row_per_check(loop_env):
    set_health(loop_env, [HTTP_OK, HTTP_FAIL, TCP_OPEN, TCP_CLOSED])
    alert.run_alert_loop("h1", [], max_iterations=1)
    table = loop_env["console"].tables()[0]
    assert table.row_count == 4
    assert table.columns[0]._cells == ["http:80", "http:8080", "tcp:22", "tcp:443"]
    assert table.columns[1]._cells == [
        "[green]200[/green]",
        "[red]500[/red]",
        "[green]open[/green]",
        "[red]closed[/red]",
    ]


def test_run_alert_loop_renders_erro_marker_for_an_http_check_with_no_status(loop_env):
    set_health(loop_env, [HTTP_ERROR])
    alert.run_alert_loop("h1", [], max_iterations=1)
    assert loop_env["console"].tables()[0].columns[1]._cells == ["[red]ERR[/red]"]


def test_run_alert_loop_renders_the_latency_column_in_milliseconds(loop_env):
    set_health(loop_env, [HTTP_OK, TCP_OPEN])
    alert.run_alert_loop("h1", [], max_iterations=1)
    assert loop_env["console"].tables()[0].columns[2]._cells == ["12.0ms", "2.0ms"]


def test_run_alert_loop_clears_the_console_before_each_render(loop_env):
    set_health(loop_env, [HTTP_OK])
    alert.run_alert_loop("h1", [], max_iterations=3)
    assert loop_env["console"].cleared == 3


def test_run_alert_loop_builds_a_webhook_sink_from_the_legacy_webhook_argument(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    alert.run_alert_loop("h1", [], max_iterations=1, webhook="https://example.com/hook")
    assert "Sinks: webhook" in loop_env["console"].lines()


def test_run_alert_loop_builds_a_slack_sink_from_the_legacy_slack_flag(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    alert.run_alert_loop(
        "h1", [], max_iterations=1, webhook="https://hooks.slack.com/x", slack=True
    )
    assert "Sinks: slack" in loop_env["console"].lines()


def test_run_alert_loop_accepts_extra_webhooks_alongside_legacy_args(loop_env):
    set_health(loop_env, [HTTP_FAIL])
    alert.run_alert_loop(
        "h1",
        [],
        max_iterations=1,
        webhook="https://a.example",
        extra_webhooks=["https://b.example"],
    )
    assert "Sinks: webhook, webhook" in loop_env["console"].lines()
