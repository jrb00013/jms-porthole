"""Unit tests for porthole.probe — banner grabbing and fingerprinting, no real sockets."""

import socket
import ssl
from io import StringIO

import pytest
from rich.console import Console

from porthole import probe


class FakeConn:
    """Stand-in for the socket returned by socket.create_connection / wrap_socket."""

    def __init__(self, banner=b"", send_error=None, recv_error=None, peer_cert=None):
        self.banner = banner
        self.send_error = send_error
        self.recv_error = recv_error
        self.peer_cert = peer_cert
        self.sent = []
        self.timeouts = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, data):
        if self.send_error:
            raise self.send_error
        self.sent.append(data)

    def recv(self, n):
        if self.recv_error:
            raise self.recv_error
        return self.banner[:n]

    def getpeercert(self, binary_form=False):
        if self.peer_cert is None:
            return None
        return self.peer_cert

    def close(self):
        self.closed = True


class FakeSSLContext:
    def __init__(self, peer_cert=None, banner=b""):
        self.peer_cert = peer_cert
        self.banner = banner
        self.wrapped = []
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, sock, server_hostname=None, **_):
        conn = FakeConn(banner=self.banner, peer_cert=self.peer_cert)
        conn.wrapped_from = sock
        conn.server_hostname = server_hostname
        self.wrapped.append(conn)
        return conn


class ConnectRecorder:
    """Callable stand-in for socket.create_connection that records every call."""

    def __init__(self, monkeypatch):
        self.calls = []
        self.conns = []
        self.error = None
        self.fail_after_first = False
        self.ctx = FakeSSLContext()
        monkeypatch.setattr(probe.socket, "create_connection", self)
        monkeypatch.setattr(probe.ssl, "create_default_context", lambda: self.ctx)

    def configure(self, conns=None, error=None, peer_cert=None, ssl_banner=b""):
        self.conns = list(conns or [])
        self.error = error
        self.fail_after_first = False
        self.ctx = FakeSSLContext(peer_cert=peer_cert, banner=ssl_banner)
        return self

    def __call__(self, address, timeout=None):
        self.calls.append((address, timeout))
        if self.fail_after_first and len(self.calls) > 1:
            raise OSError("cert fetch failed")
        if self.error:
            raise self.error
        if len(self.conns) == 1:
            return self.conns[0]
        return self.conns.pop(0)


@pytest.fixture
def connect(monkeypatch):
    return ConnectRecorder(monkeypatch)


@pytest.fixture
def connect_factory(monkeypatch):
    def install(conns=None, error=None, peer_cert=None):
        recorder = ConnectRecorder(monkeypatch)
        recorder.configure(conns=conns, error=error, peer_cert=peer_cert)
        return recorder

    return install


# --- probe_service: openness --------------------------------------------------


def test_probe_service_marks_open_when_connection_succeeds(connect_factory):
    connect_factory([FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n")])
    assert probe.probe_service("10.0.0.1", 22)["open"] is True


def test_probe_service_marks_closed_on_connection_refused(connect_factory):
    connect_factory(error=ConnectionRefusedError())
    result = probe.probe_service("10.0.0.1", 22)
    assert result["open"] is False
    assert result["banner"] == ""


def test_probe_service_marks_closed_on_socket_timeout(connect_factory):
    connect_factory(error=socket.timeout())
    assert probe.probe_service("10.0.0.1", 22)["open"] is False


def test_probe_service_marks_closed_on_generic_oserror(connect_factory):
    connect_factory(error=OSError("Network is unreachable"))
    assert probe.probe_service("10.0.0.1", 22)["open"] is False


def test_probe_service_still_open_when_only_the_banner_read_fails(connect_factory):
    """A server that accepts then hangs leaves open=True with an empty banner."""
    connect_factory([FakeConn(recv_error=socket.timeout())])
    result = probe.probe_service("10.0.0.1", 22)
    assert result["open"] is True
    assert result["banner"] == ""
    assert result["version"] == ""


def test_probe_service_closes_the_connection_after_probing(connect_factory):
    conn = FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 22)
    assert conn.closed is True


def test_probe_service_applies_timeout_to_the_connection(connect):
    conn = FakeConn(b"")
    connect.configure([conn])
    probe.probe_service("10.0.0.1", 22, timeout=4.0)
    assert conn.timeouts == [4.0]
    assert connect.calls == [(("10.0.0.1", 22), 4.0)]


# --- probe_service: service names ---------------------------------------------


@pytest.mark.parametrize(
    "port,service",
    [
        (22, "SSH"),
        (21, "FTP"),
        (25, "SMTP"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (27017, "MongoDB"),
        (3389, "RDP"),
        (5900, "VNC"),
    ],
)
def test_probe_service_reports_known_service_name(connect_factory, port, service):
    connect_factory([FakeConn(b"")])
    assert probe.probe_service("10.0.0.1", port)["service"] == service


def test_probe_service_unknown_port_reports_unknown_service(connect_factory):
    connect_factory([FakeConn(b"")])
    result = probe.probe_service("10.0.0.1", 9999)
    assert result["service"] == "unknown"
    assert result["open"] is True


def test_probe_service_unknown_port_sends_no_probe_data(connect_factory):
    conn = FakeConn(b"")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 9999)
    assert conn.sent == []


def test_probe_service_https_port_reports_https_service(connect_factory):
    connect_factory([FakeConn(b"")])
    assert probe.probe_service("10.0.0.1", 443)["service"] == "HTTPS"


# --- probe_service: payloads sent ---------------------------------------------


def test_probe_service_smtp_sends_ehlo_payload(connect_factory):
    conn = FakeConn(b"")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 25)
    assert conn.sent == [b"EHLO jms\r\n"]


def test_probe_service_http_sends_head_request_with_host_header(connect_factory):
    conn = FakeConn(b"HTTP/1.1 200 OK\r\n")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 80)
    assert conn.sent == [b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"]


def test_probe_service_redis_sends_ping(connect_factory):
    conn = FakeConn(b"+PONG\r\n")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 6379)
    assert conn.sent == [b"PING\r\n"]


def test_probe_service_ssh_sends_nothing_and_only_reads(connect_factory):
    conn = FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n")
    connect_factory([conn])
    probe.probe_service("10.0.0.1", 22)
    assert conn.sent == []


# --- probe_service: version fingerprinting ------------------------------------


def test_probe_service_extracts_ssh_protocol_version(connect_factory):
    connect_factory([FakeConn(b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-3ubuntu0.4\r\n")])
    result = probe.probe_service("10.0.0.1", 22)
    assert result["version"] == "2.0-OpenSSH_9.2p1"


def test_probe_service_extracts_nginx_version_from_server_header(connect_factory):
    connect_factory([FakeConn(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n")])
    result = probe.probe_service("10.0.0.1", 80)
    assert result["version"] == "nginx/1.24.0"


def test_probe_service_extracts_apache_version_from_server_header(connect_factory):
    connect_factory([FakeConn(b"HTTP/1.0 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\n")])
    result = probe.probe_service("10.0.0.1", 80)
    assert result["version"] == "Apache/2.4.57 (Ubuntu)"


def test_probe_service_extracts_x_powered_by_header(connect_factory):
    connect_factory([FakeConn(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.1\r\n")])
    assert probe.probe_service("10.0.0.1", 80)["version"] == "PHP/8.2.1"


def test_probe_service_redis_pong_uses_label_because_pattern_has_no_group(connect_factory):
    connect_factory([FakeConn(b"+PONG\r\n")])
    assert probe.probe_service("10.0.0.1", 6379)["version"] == "Redis"


def test_probe_service_extracts_mysql_version(connect_factory):
    connect_factory([FakeConn(b"\x0f\x00\x00\x005.7.42-log\x00")])
    assert probe.probe_service("10.0.0.1", 3306)["version"] == "7.42"


def test_probe_service_smtp_220_banner_matches_ftp_smtp_pattern(connect_factory):
    connect_factory([FakeConn(b"220 mail.example.com ESMTP Postfix\r\n")])
    assert probe.probe_service("10.0.0.1", 25)["version"] == "mail.example.com ESMTP Postfix"


def test_probe_service_ftp_banner_matches_ftp_smtp_pattern(connect_factory):
    connect_factory([FakeConn(b"220 ProFTPD 1.3.5 Server ready\r\n")])
    assert probe.probe_service("10.0.0.1", 21)["version"] == "ProFTPD 1.3.5 Server ready"


def test_probe_service_unknown_banner_leaves_version_empty(connect_factory):
    connect_factory([FakeConn(b"\x01\x02\x03\x04 binary junk\r\n")])
    assert probe.probe_service("10.0.0.1", 9999)["version"] == ""


def test_probe_service_ssh_pattern_wins_over_openssh_pattern(connect_factory):
    r"""VERSION_PATTERNS is ordered, so SSH-(\S+) matches before OpenSSH[_/]."""
    connect_factory([FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n")])
    assert probe.probe_service("10.0.0.1", 22)["version"] != "OpenSSH_9.2p1"


def test_probe_service_strips_banner_whitespace(connect_factory):
    connect_factory([FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n\r\n")])
    assert probe.probe_service("10.0.0.1", 22)["banner"] == "SSH-2.0-OpenSSH_9.2p1"


def test_probe_service_truncates_banner_to_200_chars(connect_factory):
    connect_factory([FakeConn(b"A" * 500)])
    assert len(probe.probe_service("10.0.0.1", 9999)["banner"]) == 200


def test_probe_service_decodes_undecodable_bytes_with_replacement(connect_factory):
    connect_factory([FakeConn(b"\xff\xfe\x00SSH-ish\r\n")])
    result = probe.probe_service("10.0.0.1", 9999)
    assert "\ufffd" in result["banner"]


def test_probe_service_result_has_the_expected_key_set(connect_factory):
    connect_factory([FakeConn(b"")])
    result = probe.probe_service("10.0.0.1", 22)
    assert set(result) == {"port", "open", "service", "banner", "version"}
    assert result["port"] == 22


# --- probe_service: TLS on 443 ------------------------------------------------


def test_probe_service_https_disables_hostname_check_and_verification(connect):
    connect.configure([FakeConn(b"")])
    probe.probe_service("10.0.0.1", 443)
    assert connect.ctx.check_hostname is False
    assert connect.ctx.verify_mode == ssl.CERT_NONE


def test_probe_service_https_passes_host_as_server_hostname(connect):
    connect.configure([FakeConn(b"")])
    probe.probe_service("web.example.com", 443)
    assert connect.ctx.wrapped[0].server_hostname == "web.example.com"


def test_probe_service_https_attaches_tls_common_name_and_expiry(connect):
    peer = {
        "subject": ((("commonName", "web.example.com"),),),
        "notAfter": "Jun  1 12:00:00 2027 GMT",
    }
    connect.configure([FakeConn(b"")], peer_cert=peer)
    result = probe.probe_service("web.example.com", 443)
    assert result["tls_cn"] == "web.example.com"
    assert result["tls_expiry"] == "Jun  1 12:00:00 2027 GMT"


def test_probe_service_https_opens_a_second_connection_for_the_cert(connect):
    connect.configure([FakeConn(b""), FakeConn(b"")])
    probe.probe_service("10.0.0.1", 443)
    assert len(connect.calls) == 2


def test_probe_service_non_tls_port_opens_only_one_connection(connect):
    connect.configure([FakeConn(b"")])
    probe.probe_service("10.0.0.1", 80)
    assert len(connect.calls) == 1


def test_probe_service_https_without_peer_cert_reports_empty_cn(connect):
    connect.configure([FakeConn(b"")], peer_cert={})
    result = probe.probe_service("10.0.0.1", 443)
    assert result["tls_cn"] == ""
    assert result["tls_expiry"] == ""


def test_probe_service_https_marks_closed_when_tls_handshake_fails(connect):
    connect.configure([FakeConn(b"")])

    def boom(sock, server_hostname=None, **_):
        raise ssl.SSLError("handshake failure")

    connect.ctx.wrap_socket = boom
    result = probe.probe_service("10.0.0.1", 443)
    assert result["open"] is False
    assert result["banner"] == ""


def test_probe_service_https_cert_fetch_failure_still_keeps_banner(connect):
    """The cert re-connect is best-effort; the banner result must survive."""
    peer = {
        "subject": ((("commonName", "web.example.com"),),),
        "notAfter": "Jun  1 12:00:00 2027 GMT",
    }
    connect.configure(
        [FakeConn(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n")],
        peer_cert=peer,
        ssl_banner=b"HTTP/1.1 200 OK\r\nServer: nginx\r\n",
    )
    connect.fail_after_first = True
    result = probe.probe_service("10.0.0.1", 443)
    assert result["open"] is True
    assert result["version"] == "nginx"
    assert "tls_cn" not in result


# --- probe_host ---------------------------------------------------------------


def test_probe_host_returns_only_open_services(connect_factory):
    connect_factory([FakeConn(b"SSH-2.0-OpenSSH_9.2p1\r\n")], error=None)
    results = probe.probe_host("10.0.0.1", ports=[22])
    assert [r["port"] for r in results] == [22]


def test_probe_host_returns_empty_list_when_nothing_is_open(connect_factory):
    connect_factory(error=ConnectionRefusedError())
    assert probe.probe_host("10.0.0.1", ports=[22, 80]) == []


def test_probe_host_probes_ports_in_sorted_order(monkeypatch):
    seen = []

    def fake_probe(host, port, timeout=3.0):
        seen.append(port)
        return {"port": port, "open": port == 22}

    monkeypatch.setattr(probe, "probe_service", fake_probe)
    probe.probe_host("10.0.0.1", ports=[443, 22, 80])
    assert seen == [22, 80, 443]


def test_probe_host_keeps_only_the_open_ones(monkeypatch):
    monkeypatch.setattr(
        probe,
        "probe_service",
        lambda host, port, timeout=3.0: {"port": port, "open": port in (22, 443)},
    )
    results = probe.probe_host("10.0.0.1", ports=[22, 80, 443])
    assert [r["port"] for r in results] == [22, 443]


def test_probe_host_defaults_to_every_service_probe_port(connect_factory):
    connect_factory([FakeConn(b"")])
    results = probe.probe_host("10.0.0.1")
    assert len(results) == len(probe.SERVICE_PROBES)
    assert sorted(r["port"] for r in results) == sorted(probe.SERVICE_PROBES)


def test_probe_host_default_port_list_is_sorted_in_result_order(connect_factory):
    connect_factory([FakeConn(b"")])
    ports = [r["port"] for r in probe.probe_host("10.0.0.1")]
    assert ports == sorted(ports)


def test_probe_host_empty_port_list_returns_nothing(connect_factory):
    connect_factory([FakeConn(b"")])
    assert probe.probe_host("10.0.0.1", ports=[]) == []


# --- print_probe_results ------------------------------------------------------


def _capture_console(monkeypatch):
    buf = StringIO()
    monkeypatch.setattr(probe, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_print_probe_results_reports_no_open_services(monkeypatch):
    buf = _capture_console(monkeypatch)
    probe.print_probe_results("10.0.0.1", [])
    out = buf.getvalue()
    assert "No open services found" in out
    assert "10.0.0.1" in out


def test_print_probe_results_shows_port_service_and_version(monkeypatch):
    buf = _capture_console(monkeypatch)
    probe.print_probe_results(
        "10.0.0.1",
        [
            {
                "port": 22,
                "open": True,
                "service": "SSH",
                "version": "2.0-OpenSSH_9.2p1",
                "banner": "SSH-2.0-OpenSSH_9.2p1",
            },
        ],
    )
    out = buf.getvalue()
    assert "22" in out
    assert "SSH" in out
    assert "2.0-OpenSSH_9.2p1" in out


def test_print_probe_results_truncates_banner_to_80_chars(monkeypatch):
    buf = _capture_console(monkeypatch)
    probe.print_probe_results(
        "10.0.0.1",
        [
            {"port": 9999, "open": True, "service": "unknown", "version": "", "banner": "B" * 300},
        ],
    )
    assert "B" * 300 not in buf.getvalue()


def test_print_probe_results_renders_empty_banner_cell(monkeypatch):
    buf = _capture_console(monkeypatch)
    probe.print_probe_results(
        "10.0.0.1",
        [
            {"port": 22, "open": True, "service": "SSH", "version": "", "banner": ""},
        ],
    )
    assert "SSH" in buf.getvalue()


def test_print_probe_results_handles_missing_version_key(monkeypatch):
    buf = _capture_console(monkeypatch)
    probe.print_probe_results(
        "10.0.0.1",
        [
            {"port": 22, "open": True, "service": "SSH", "banner": "x"},
        ],
    )
    assert "SSH" in buf.getvalue()
