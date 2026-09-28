"""Unit tests for porthole.sinks — webhook/Slack/email alert fan-out."""

from unittest.mock import MagicMock, patch

from porthole import sinks


def test_webhook_sink_posts_generic_payload():
    with patch.object(sinks, "_post_json", return_value=True) as post_mock:
        sink = sinks.WebhookSink("https://example.com/hook")
        assert sink.notify("host1", [{"name": "tcp:22", "error": "down"}]) is True
    payload = post_mock.call_args[0][1]
    assert payload["host"] == "host1"
    assert payload["failures"][0]["name"] == "tcp:22"


def test_slack_sink_posts_text_payload():
    with patch.object(sinks, "_post_json", return_value=True) as post_mock:
        sink = sinks.SlackSink("https://hooks.slack.com/x")
        sink.notify("host1", [{"name": "http:80", "status": 500}])
    payload = post_mock.call_args[0][1]
    assert "text" in payload
    assert "host1" in payload["text"]


def test_email_sink_sends_via_smtp():
    mock_server = MagicMock()
    mock_server.__enter__.return_value = mock_server
    with patch("smtplib.SMTP", return_value=mock_server):
        sink = sinks.EmailSink(
            "smtp.example.com", "from@example.com", "to@example.com", username="u", password="p"
        )
        result = sink.notify("host1", [{"name": "tcp:22", "error": "down"}])

    assert result is True
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("u", "p")
    mock_server.sendmail.assert_called_once()


def test_email_sink_returns_false_on_smtp_error():
    with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
        sink = sinks.EmailSink("smtp.example.com", "from@example.com", "to@example.com")
        assert sink.notify("host1", [{"name": "tcp:22"}]) is False


def test_notify_all_fans_out_to_every_sink():
    sink_a = MagicMock()
    sink_a.name = "a"
    sink_a.notify.return_value = True
    sink_b = MagicMock()
    sink_b.name = "b"
    sink_b.notify.return_value = False

    outcomes = sinks.notify_all([sink_a, sink_b], "host1", [{"name": "x"}])
    assert outcomes == {"a": True, "b": False}
    sink_a.notify.assert_called_once_with("host1", [{"name": "x"}])
    sink_b.notify.assert_called_once_with("host1", [{"name": "x"}])


def test_post_json_returns_false_on_url_error():
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
        assert sinks._post_json("https://example.com", {"a": 1}, 5.0) is False
