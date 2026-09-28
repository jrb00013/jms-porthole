"""Extra unit tests for porthole.health — HTTPS check construction, measured
latency, failure classification, and the result renderer.

`http.client`, `ssl` and `socket.create_connection` are always patched, so no
real socket, TLS handshake or HTTP request is made.
"""

import io
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from porthole import health


@pytest.fixture
def console_buf(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(health, "console", Console(file=buf, width=250, no_color=True))
    return buf


def _http_conn(status=200, body=b"ok"):
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    conn = MagicMock()
    conn.getresponse.return_value = resp
    return conn


# ── check_http ────────────────────────────────────────────────────────────────


def test_check_http_measures_latency_from_monotonic_clock():
    conn = _http_conn()
    with (
        patch("http.client.HTTPConnection", return_value=conn),
        patch("time.monotonic", side_effect=[10.0, 10.1234]),
    ):
        result = health.check_http("10.0.0.1", 80, "/")

    assert result["latency_ms"] == 123.4
    assert isinstance(result["latency_ms"], float)


def test_check_http_rounds_latency_to_one_decimal_place():
    conn = _http_conn()
    with (
        patch("http.client.HTTPConnection", return_value=conn),
        patch("time.monotonic", side_effect=[0.0, 0.000_456]),
    ):
        result = health.check_http("10.0.0.1", 80, "/")

    assert result["latency_ms"] == 0.5


def test_check_http_sends_get_with_host_header_and_closes_connection():
    conn = _http_conn()
    with patch("http.client.HTTPConnection", return_value=conn):
        health.check_http("example.com", 8080, "/status")

    conn.request.assert_called_once_with("GET", "/status", headers={"Host": "example.com"})
    conn.close.assert_called_once()


def test_check_http_truncates_snippet_to_eighty_characters():
    conn = _http_conn(body=b"x" * 500)
    with patch("http.client.HTTPConnection", return_value=conn):
        result = health.check_http("10.0.0.1", 80, "/")

    assert len(result["snippet"]) == 80


def test_check_http_decodes_undecodable_bytes_without_raising():
    conn = _http_conn(body=b"\xff\xfe binary")
    with patch("http.client.HTTPConnection", return_value=conn):
        result = health.check_http("10.0.0.1", 80, "/")

    assert "binary" in result["snippet"]


def test_check_http_https_builds_insecure_context_and_uses_https_connection():
    ctx = MagicMock()
    conn = _http_conn(status=200)
    with (
        patch("ssl.create_default_context", return_value=ctx) as ctx_factory,
        patch("http.client.HTTPSConnection", return_value=conn) as https_conn,
        patch("http.client.HTTPConnection") as plain_conn,
    ):
        result = health.check_http("example.com", 443, "/api", https=True)

    ctx_factory.assert_called_once_with()
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
    https_conn.assert_called_once_with(
        "example.com", 443, timeout=health.CHECK_TIMEOUT, context=ctx
    )
    plain_conn.assert_not_called()
    assert result["status"] == 200


def test_check_http_https_measures_latency_like_the_plain_http_path():
    ctx = MagicMock()
    conn = _http_conn(status=204)
    with (
        patch("ssl.create_default_context", return_value=ctx),
        patch("http.client.HTTPSConnection", return_value=conn),
        patch("time.monotonic", side_effect=[5.0, 5.05]),
    ):
        result = health.check_http("example.com", 443, "/", https=True)

    assert result["latency_ms"] == 50.0
    assert result["status"] == 204


def test_check_http_https_reports_connection_failure_with_null_status():
    with (
        patch("ssl.create_default_context", return_value=MagicMock()),
        patch("http.client.HTTPSConnection", side_effect=ssl.SSLError("handshake failed")),
    ):
        result = health.check_http("example.com", 443, "/", https=True)

    assert result["status"] is None
    assert result["latency_ms"] is None
    assert "handshake failed" in result["snippet"]


def test_check_http_timeout_reports_null_status_and_timeout_snippet():
    with patch("http.client.HTTPConnection", side_effect=socket.timeout("timed out")):
        result = health.check_http("10.0.0.1", 80, "/")

    assert result["status"] is None
    assert result["latency_ms"] is None
    assert "timed out" in result["snippet"]


def test_check_http_dns_failure_is_reported_in_snippet_not_raised():
    with patch(
        "http.client.HTTPConnection", side_effect=socket.gaierror(-2, "Name or service not known")
    ):
        result = health.check_http("nope.invalid", 80, "/")

    assert result["status"] is None
    assert "Name or service not known" in result["snippet"]


def test_check_http_uses_the_configured_check_timeout():
    conn = _http_conn()
    with patch("http.client.HTTPConnection", return_value=conn) as http_conn:
        health.check_http("10.0.0.1", 8080, "/")

    assert http_conn.call_args.kwargs["timeout"] == health.CHECK_TIMEOUT == 3.0


# ── check_tcp ─────────────────────────────────────────────────────────────────


def test_check_tcp_measures_latency_from_monotonic_clock():
    with (
        patch("socket.create_connection") as conn,
        patch("time.monotonic", side_effect=[2.0, 2.0075]),
    ):
        conn.return_value.__enter__.return_value = MagicMock()
        result = health.check_tcp("10.0.0.1", 22)

    assert result == {"port": 22, "open": True, "latency_ms": 7.5}


def test_check_tcp_timeout_is_classified_as_closed():
    with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
        result = health.check_tcp("10.0.0.1", 22)

    assert result["open"] is False
    assert "timed out" in result["error"]


def test_check_tcp_dns_failure_is_classified_as_closed():
    with patch(
        "socket.create_connection", side_effect=socket.gaierror(-2, "Name or service not known")
    ):
        result = health.check_tcp("nope.invalid", 80)

    assert result["open"] is False
    assert "Name or service not known" in result["error"]


def test_check_tcp_truncates_the_error_message_to_sixty_characters():
    with patch("socket.create_connection", side_effect=OSError("e" * 200)):
        result = health.check_tcp("10.0.0.1", 22)

    assert len(result["error"]) == 60


def test_check_tcp_uses_the_configured_check_timeout():
    with patch("socket.create_connection") as conn:
        conn.return_value.__enter__.return_value = MagicMock()
        health.check_tcp("10.0.0.1", 22)

    assert conn.call_args.kwargs["timeout"] == health.CHECK_TIMEOUT


# ── run_health_checks dispatch ────────────────────────────────────────────────


def test_run_health_checks_passes_https_flag_and_path_through_to_check_http():
    checks = [{"type": "http", "port": 443, "path": "/api", "https": True, "name": "https:443/api"}]
    with patch.object(health, "check_http", return_value={"port": 443, "status": 200}) as http_mock:
        results = health.run_health_checks("host", checks)

    http_mock.assert_called_once_with("host", 443, "/api", True)
    assert results[0]["name"] == "https:443/api"
    assert results[0]["type"] == "http"


@pytest.mark.xfail(
    reason="source bug: run_health_checks formats default name using c['port'] even when missing for http checks",
    strict=True,
)
def test_run_health_checks_defaults_http_port_to_80_and_path_to_slash():
    with patch.object(health, "check_http", return_value={}) as http_mock:
        health.run_health_checks("host", [{"type": "http"}])

    http_mock.assert_called_once_with("host", 80, "/", False)


def test_run_health_checks_uses_custom_name_when_provided():
    checks = [{"type": "tcp", "port": 22, "name": "ssh"}]
    with patch.object(health, "check_tcp", return_value={"open": True}):
        results = health.run_health_checks("host", checks)

    assert results[0]["name"] == "ssh"


def test_run_health_checks_returns_one_result_per_check_in_order():
    checks = [
        {"type": "tcp", "port": 22},
        {"type": "http", "port": 80},
        {"type": "tcp", "port": 443},
    ]

    def fresh_tcp(host, port):
        return {"port": port, "open": True, "latency_ms": 1.0}

    def fresh_http(host, port, path, https):
        return {"port": port, "status": 200, "latency_ms": 2.0, "snippet": ""}

    with (
        patch.object(health, "check_tcp", side_effect=fresh_tcp),
        patch.object(health, "check_http", side_effect=fresh_http),
    ):
        results = health.run_health_checks("host", checks)

    assert [r["name"] for r in results] == ["tcp:22", "http:80", "tcp:443"]
    assert [r["type"] for r in results] == ["tcp", "http", "tcp"]


# ── parse_check_specs ─────────────────────────────────────────────────────────


def test_parse_check_specs_https_without_path_defaults_to_root():
    parsed = health.parse_check_specs(("https:443",))

    assert parsed == [
        {"type": "http", "port": 443, "path": "/", "https": True, "name": "https:443"}
    ]


def test_parse_check_specs_trailing_slash_yields_root_path():
    assert health.parse_check_specs(("http:80/",))[0]["path"] == "/"


def test_parse_check_specs_lowercases_type_but_keeps_original_name():
    parsed = health.parse_check_specs(("HTTPS:443/api", "TCP:22"))

    assert parsed[0]["type"] == "http"
    assert parsed[0]["https"] is True
    assert parsed[0]["name"] == "HTTPS:443/api"
    assert parsed[1]["type"] == "tcp"
    assert parsed[1]["name"] == "TCP:22"


def test_parse_check_specs_treats_unknown_scheme_as_a_tcp_check():
    parsed = health.parse_check_specs(("ssh:2222",))

    assert parsed == [{"type": "tcp", "port": 2222, "name": "ssh:2222"}]


def test_parse_check_specs_drops_everything_after_a_second_colon():
    """Pins current behaviour: `spec.split(":", 2)` keeps at most 2 colons, so a
    colon inside the path (e.g. 'http:8080/a:b') is silently truncated to '/a'."""
    parsed = health.parse_check_specs(("http:8080/a:b",))

    assert parsed[0]["port"] == 8080
    assert parsed[0]["path"] == "/a"
    assert parsed[0]["name"] == "http:8080/a:b"


def test_parse_check_specs_drops_specs_without_a_colon_but_keeps_the_rest():
    parsed = health.parse_check_specs(("garbage", "tcp:22", "", "udp:53"))

    assert [c["name"] for c in parsed] == ["tcp:22", "udp:53"]


# ── print_health_results ──────────────────────────────────────────────────────


def test_print_health_results_titles_the_table_with_the_host(console_buf):
    health.print_health_results(
        "10.0.0.1", [{"type": "tcp", "name": "tcp:22", "open": True, "latency_ms": 1.0}]
    )

    out = console_buf.getvalue()
    assert "Health Checks — 10.0.0.1" in out
    for header in ("Service", "Status", "Latency", "Detail"):
        assert header in out


def test_print_health_results_marks_2xx_http_as_healthy_with_latency(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "http",
                "name": "http:80",
                "status": 200,
                "latency_ms": 12.5,
                "snippet": "hello",
            }
        ],
    )

    out = console_buf.getvalue()
    assert "200" in out
    assert "12.5ms" in out
    assert "hello" in out
    assert "ERR" not in out


def test_print_health_results_treats_3xx_redirects_as_healthy(console_buf):
    health.print_health_results(
        "host",
        [{"type": "http", "name": "http:80", "status": 302, "latency_ms": 3.0, "snippet": ""}],
    )

    out = console_buf.getvalue()
    assert "302" in out
    assert "ERR" not in out


def test_print_health_results_marks_non_2xx_http_as_failed(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "http",
                "name": "http:80",
                "status": 503,
                "latency_ms": 1.0,
                "snippet": "upstream down",
            }
        ],
    )

    out = console_buf.getvalue()
    assert "503" in out
    assert "upstream down" in out


def test_print_health_results_shows_ERR_when_http_check_never_got_a_status(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "http",
                "name": "https:443",
                "status": None,
                "latency_ms": None,
                "snippet": "timed out",
            }
        ],
    )

    out = console_buf.getvalue()
    assert "ERR" in out
    assert "timed out" in out
    assert "—" in out, "missing latency should render as an em dash"


def test_print_health_results_shows_ERR_for_a_zero_status_code(console_buf):
    health.print_health_results(
        "host", [{"type": "http", "name": "http:80", "status": 0, "latency_ms": 0.0, "snippet": ""}]
    )

    assert "ERR" in console_buf.getvalue()


def test_print_health_results_marks_open_tcp_as_green(console_buf):
    health.print_health_results(
        "host", [{"type": "tcp", "name": "tcp:22", "open": True, "latency_ms": 4.2}]
    )

    out = console_buf.getvalue()
    assert "open" in out
    assert "4.2ms" in out
    assert "closed" not in out


def test_print_health_results_marks_closed_tcp_with_its_error(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "tcp",
                "name": "tcp:22",
                "open": False,
                "latency_ms": None,
                "error": "Connection refused",
            }
        ],
    )

    out = console_buf.getvalue()
    assert "closed" in out
    assert "Connection refused" in out
    assert "—" in out


def test_print_health_results_treats_missing_open_key_as_closed(console_buf):
    health.print_health_results("host", [{"type": "tcp", "name": "tcp:22", "latency_ms": None}])

    out = console_buf.getvalue()
    assert "closed" in out


def test_print_health_results_truncates_http_snippet_to_sixty_characters(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "http",
                "name": "http:80",
                "status": 200,
                "latency_ms": 1.0,
                "snippet": "s" * 200,
            }
        ],
    )

    # Rich may ellipsize the cell further; assert the source truncates to 60.
    out = console_buf.getvalue().replace("…", "").replace("...", "")
    assert "s" * 40 in out
    assert "s" * 61 not in out


def test_print_health_results_renders_every_result_row(console_buf):
    health.print_health_results(
        "host",
        [
            {
                "type": "http",
                "name": "https:443",
                "status": 200,
                "latency_ms": 9.0,
                "snippet": "ok",
            },
            {"type": "tcp", "name": "tcp:22", "open": True, "latency_ms": 1.0},
            {"type": "tcp", "name": "tcp:3306", "open": False, "latency_ms": None, "error": "down"},
        ],
    )

    out = console_buf.getvalue()
    for name in ("https:443", "tcp:22", "tcp:3306"):
        assert name in out
    assert "9.0ms" in out
    assert "down" in out


def test_print_health_results_handles_an_empty_result_list(console_buf):
    health.print_health_results("host", [])

    out = console_buf.getvalue()
    assert "Health Checks — host" in out
    assert "Service" in out
