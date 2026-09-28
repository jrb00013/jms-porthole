"""Unit tests for porthole.alert — sink construction (no real network/loops)."""

from porthole import alert
from porthole.sinks import SlackSink, WebhookSink


def test_build_sinks_empty_when_nothing_configured():
    assert alert.build_sinks() == []


def test_build_sinks_webhook_only():
    result = alert.build_sinks(webhook="https://example.com/hook")
    assert len(result) == 1
    assert isinstance(result[0], WebhookSink)


def test_build_sinks_slack_flag_uses_slack_sink():
    result = alert.build_sinks(webhook="https://hooks.slack.com/x", slack=True)
    assert len(result) == 1
    assert isinstance(result[0], SlackSink)


def test_build_sinks_extra_webhooks_are_appended():
    result = alert.build_sinks(
        webhook="https://a.com", extra_webhooks=["https://b.com", "https://c.com"]
    )
    assert len(result) == 3
    assert all(isinstance(s, WebhookSink) for s in result)


def test_build_sinks_includes_prebuilt_sinks():
    class FakeSink:
        name = "fake"

        def notify(self, host, failures):
            return True

    fake = FakeSink()
    result = alert.build_sinks(sinks=[fake])
    assert result == [fake]
