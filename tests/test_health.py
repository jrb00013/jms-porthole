"""Unit tests for porthole.health — parsing and check logic, no real network."""
from unittest.mock import patch, MagicMock

from porthole import health


def test_parse_tcp_spec():
    checks = health.parse_check_specs(("tcp:22",))
    assert checks == [{"type": "tcp", "port": 22, "name": "tcp:22"}]


def test_parse_http_spec_default_path():
    checks = health.parse_check_specs(("http:80",))
    assert checks[0] == {
        "type": "http", "port": 80, "path": "/", "https": False, "name": "http:80",
    }


def test_parse_http_spec_with_path():
    checks = health.parse_check_specs(("http:8080/status",))
    assert checks[0]["path"] == "/status"
    assert checks[0]["port"] == 8080


def test_parse_https_spec_sets_https_true():
    checks = health.parse_check_specs(("https:443/api",))
    assert checks[0]["https"] is True
    assert checks[0]["path"] == "/api"


def test_parse_multiple_specs():
    checks = health.parse_check_specs(("tcp:22", "https:443/"))
    assert len(checks) == 2
    assert checks[0]["type"] == "tcp"
    assert checks[1]["type"] == "http"


def test_parse_ignores_malformed_spec_without_colon():
    checks = health.parse_check_specs(("garbage",))
    assert checks == []


def test_check_tcp_open():
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = MagicMock()
        result = health.check_tcp("10.0.0.1", 22)
    assert result["open"] is True
    assert result["port"] == 22
    assert result["latency_ms"] is not None


def test_check_tcp_closed_reports_error():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
        result = health.check_tcp("10.0.0.1", 22)
    assert result["open"] is False
    assert result["latency_ms"] is None
    assert "error" in result


def test_check_http_success():
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"ok"
    mock_conn = MagicMock()
    mock_conn.getresponse.return_value = mock_resp

    with patch("http.client.HTTPConnection", return_value=mock_conn):
        result = health.check_http("10.0.0.1", 80, "/", https=False)

    assert result["status"] == 200
    assert result["snippet"] == "ok"


def test_check_http_connection_error_reports_body():
    with patch("http.client.HTTPConnection", side_effect=OSError("no route")):
        result = health.check_http("10.0.0.1", 80, "/", https=False)
    assert result["status"] is None
    assert "no route" in result["snippet"]


def test_run_health_checks_dispatches_by_type():
    checks = [{"type": "tcp", "port": 22}, {"type": "http", "port": 80, "path": "/"}]
    with patch.object(health, "check_tcp", return_value={"port": 22, "open": True, "latency_ms": 1.0}) as tcp_mock, \
         patch.object(health, "check_http", return_value={"port": 80, "status": 200, "latency_ms": 2.0, "snippet": ""}) as http_mock:
        results = health.run_health_checks("host", checks)

    tcp_mock.assert_called_once()
    http_mock.assert_called_once()
    assert results[0]["name"] == "tcp:22"
    assert results[1]["name"] == "http:80"
