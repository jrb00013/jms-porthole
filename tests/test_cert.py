"""Unit tests for porthole.cert — TLS expiry parsing via faked sockets, no real network."""

import ssl
from datetime import datetime, timedelta, timezone
from io import StringIO

import pytest
from rich.console import Console

from porthole import cert


def make_cert_dict(
    not_after=None,
    cn="example.com",
    issuer_cn="Example CA",
    san=(("DNS", "example.com"), ("DNS", "www.example.com")),
):
    """Build a dict-form peer cert the way ssl.SSLSocket.getpeercert() does."""
    c = {
        "subject": ((("commonName", cn),), (("organizationName", "Example Inc"),)),
        "issuer": ((("commonName", issuer_cn),),),
        "subjectAltName": tuple(san),
        "serialNumber": "0A1B2C3D",
    }
    if not_after is not None:
        c["notAfter"] = not_after
    return c


NOT_AFTER_BIAS_HOURS = 1


def ssl_not_after(days=0):
    """Format a notAfter the way ssl does: 'Jun  1 12:00:00 2027 GMT'.

    A 1-hour bias is added so the whole seconds field survives the strftime
    truncation and the truncated day count is exactly `days`.
    """
    when = datetime.now(timezone.utc) + timedelta(days=days, hours=NOT_AFTER_BIAS_HOURS)
    return when.strftime("%b %d %H:%M:%S %Y GMT")


class FakeRawSock:
    def __init__(self, name="raw"):
        self.name = name
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def close(self):
        self.closed = True


class FakeSSLSock(FakeRawSock):
    def __init__(self, peer_cert, name="ssl", recv_data=b""):
        super().__init__(name)
        self._peer_cert = peer_cert
        self.recv_data = recv_data
        self.sent = []

    def getpeercert(self, binary_form=False):
        return self._peer_cert

    def settimeout(self, _):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        return self.recv_data[:n]

    def getpeername(self):
        return ("93.184.216.34", 443)


class FakeSSLContext:
    def __init__(self, peer_cert):
        self.peer_cert = peer_cert
        self.wrapped = []

    def wrap_socket(self, sock, server_hostname=None, **_):
        wrapped = FakeSSLSock(self.peer_cert, name=f"wrap:{server_hostname}")
        wrapped.source = sock
        self.wrapped.append(wrapped)
        return wrapped


class FakeTLSFactory:
    """Installs fake socket/ssl plumbing and records what cert.py asked for."""

    def __init__(self, monkeypatch):
        self.monkeypatch = monkeypatch
        self.conn_calls = []
        self.contexts = []
        self.socks = []

    def install(self, peer_cert):
        ctx = FakeSSLContext(peer_cert)
        self.contexts.append(ctx)
        self.monkeypatch.setattr(cert.socket, "create_connection", self._create_connection)
        self.monkeypatch.setattr(cert.ssl, "create_default_context", lambda: ctx)
        return ctx

    def _create_connection(self, address, timeout=None):
        self.conn_calls.append((address, timeout))
        sock = FakeRawSock(name=f"conn:{address}")
        self.socks.append(sock)
        return sock


@pytest.fixture
def fake_tls(monkeypatch):
    return FakeTLSFactory(monkeypatch)


# --- check_cert: field parsing -------------------------------------------------


def test_check_cert_returns_host_and_port_echoed_back(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=30)))
    result = cert.check_cert("example.com", 8443)
    assert result["host"] == "example.com"
    assert result["port"] == 8443


def test_check_cert_extracts_common_name_as_subject(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=30), cn="p.example.com"))
    result = cert.check_cert("example.com", 443)
    assert result["subject"]["commonName"] == "p.example.com"


def test_check_cert_keeps_multi_valued_subject_rdns(fake_tls):
    """A subject with several RDN tuples must keep every field, not just the first."""
    fake_tls.install(make_cert_dict(ssl_not_after(days=30), cn="multi.example.com"))
    result = cert.check_cert("example.com", 443)
    assert result["subject"] == {
        "commonName": "multi.example.com",
        "organizationName": "Example Inc",
    }


def test_check_cert_extracts_issuer_common_name(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=30), issuer_cn="DigiCert Inc"))
    result = cert.check_cert("example.com", 443)
    assert result["issuer"]["commonName"] == "DigiCert Inc"


def test_check_cert_extracts_all_subject_alt_names(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=30)))
    result = cert.check_cert("example.com", 443)
    assert result["san"] == ["example.com", "www.example.com"]


def test_check_cert_san_is_empty_list_when_absent(fake_tls):
    peer = make_cert_dict(ssl_not_after(days=30))
    del peer["subjectAltName"]
    fake_tls.install(peer)
    result = cert.check_cert("example.com", 443)
    assert result["san"] == []


def test_check_cert_connects_to_host_and_port_with_timeout(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=30)))
    cert.check_cert("example.com", 443, timeout=2.5)
    assert fake_tls.conn_calls == [(("example.com", 443), 2.5)]


def test_check_cert_passes_host_as_server_hostname(fake_tls):
    ctx = fake_tls.install(make_cert_dict(ssl_not_after(days=30)))
    cert.check_cert("example.com", 443)
    assert ctx.wrapped[0].name == "wrap:example.com"


# --- check_cert: expiry day math ----------------------------------------------


def test_check_cert_days_left_matches_days_until_not_after(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=45)))
    result = cert.check_cert("example.com", 443)
    assert result["days_left"] == 45


def test_check_cert_days_left_is_one_for_expiry_tomorrow(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=1)))
    result = cert.check_cert("example.com", 443)
    assert result["days_left"] == 1


def test_check_cert_ok_true_when_more_than_one_day_remains(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=45)))
    assert cert.check_cert("example.com", 443)["ok"] is True


def test_check_cert_ok_false_and_negative_days_when_expired_yesterday(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=-1)))
    result = cert.check_cert("example.com", 443)
    assert result["days_left"] == -1
    assert result["ok"] is False


def test_check_cert_ok_false_when_expired_ten_days_ago(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=-10)))
    result = cert.check_cert("example.com", 443)
    assert result["days_left"] == -10
    assert result["ok"] is False


def test_check_cert_expires_is_utc_isoformat_of_not_after(fake_tls):
    fake_tls.install(make_cert_dict(ssl_not_after(days=100)))
    result = cert.check_cert("example.com", 443)
    assert result["expires"].endswith("+00:00")
    assert (
        result["expires"]
        == datetime.fromisoformat(result["expires"]).astimezone(timezone.utc).isoformat()
    )


@pytest.mark.xfail(
    strict=True,
    reason="BUG cert.py:30 uses (expiry - now).days, which truncates to 0 for any "
    "cert with <24h left, so a cert that is still valid is reported ok=False.",
)
def test_check_cert_ok_true_when_twelve_hours_still_remain(fake_tls):
    """A cert expiring later today is still valid, so ok must be True."""
    when = datetime.now(timezone.utc) + timedelta(hours=12)
    fake_tls.install(make_cert_dict(when.strftime("%b %d %H:%M:%S %Y GMT")))
    result = cert.check_cert("example.com", 443)
    assert result["days_left"] == 0
    assert result["ok"] is True


# --- check_cert: failure modes -------------------------------------------------


def test_check_cert_missing_not_after_reports_no_expiry_date(fake_tls):
    fake_tls.install(make_cert_dict(None))
    result = cert.check_cert("example.com", 443)
    assert result["ok"] is False
    assert result["error"] == "no expiry date in cert"
    assert "days_left" not in result


def test_check_cert_verification_error_sets_days_left_none(monkeypatch):
    def boom(address, timeout=None):
        raise ssl.SSLCertVerificationError("certificate verify failed: self signed")

    monkeypatch.setattr(cert.socket, "create_connection", boom)
    result = cert.check_cert("bad.example.com", 443)
    assert result["ok"] is False
    assert result["days_left"] is None
    assert result["error"].startswith("verification failed: ")
    assert "certificate verify failed" in result["error"]


def test_check_cert_connection_refused_reports_short_error(monkeypatch):
    def boom(address, timeout=None):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(cert.socket, "create_connection", boom)
    result = cert.check_cert("down.example.com", 22)
    assert result["ok"] is False
    assert result["days_left"] is None
    assert "Connection refused" in result["error"]


def test_check_cert_error_message_truncated_to_100_chars(monkeypatch):
    def boom(address, timeout=None):
        raise OSError("x" * 500)

    monkeypatch.setattr(cert.socket, "create_connection", boom)
    result = cert.check_cert("down.example.com", 443)
    assert len(result["error"]) == 100


def test_check_cert_malformed_not_after_string_is_an_error(monkeypatch):
    peer = make_cert_dict("not a real date")
    ctx = FakeSSLContext(peer)
    monkeypatch.setattr(cert.socket, "create_connection", lambda a, timeout=None: FakeRawSock())
    monkeypatch.setattr(cert.ssl, "create_default_context", lambda: ctx)
    result = cert.check_cert("weird.example.com", 443)
    assert result["ok"] is False
    assert result["days_left"] is None


# --- check_certs ---------------------------------------------------------------


def test_check_certs_defaults_to_port_443(monkeypatch):
    seen = []

    def fake_check(host, port=443, timeout=5.0):
        seen.append((host, port))
        return {"host": host, "port": port, "days_left": 30}

    monkeypatch.setattr(cert, "check_cert", fake_check)
    results = cert.check_certs("example.com")
    assert seen == [("example.com", 443)]
    assert [r["port"] for r in results] == [443]


def test_check_certs_checks_every_requested_port(monkeypatch):
    seen = []
    monkeypatch.setattr(
        cert,
        "check_cert",
        lambda host, port=443, timeout=5.0: seen.append(port) or {"port": port},
    )
    results = cert.check_certs("example.com", ports=[80, 443, 8443])
    assert seen == [80, 443, 8443]
    assert [r["port"] for r in results] == [80, 443, 8443]


def test_check_certs_empty_port_list_falls_back_to_443(monkeypatch):
    """`ports or [443]` treats an empty list as 'unset'."""
    seen = []
    monkeypatch.setattr(
        cert,
        "check_cert",
        lambda h, p=443, timeout=5.0: seen.append(p) or {"port": p},
    )
    results = cert.check_certs("example.com", ports=[])
    assert seen == [443]
    assert [r["port"] for r in results] == [443]


# --- print_cert_results --------------------------------------------------------


def _capture_console(monkeypatch, module):
    buf = StringIO()
    monkeypatch.setattr(module, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_print_cert_results_marks_healthy_cert_as_ok(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results(
        "example.com",
        [
            {
                "port": 443,
                "subject": {"commonName": "example.com"},
                "expires": "2027-06-01T00:00:00+00:00",
                "days_left": 300,
                "ok": True,
            },
        ],
    )
    out = buf.getvalue()
    assert "OK" in out
    assert "300" in out
    assert "2027-06-01" in out


def test_print_cert_results_marks_13_days_as_warning(monkeypatch):
    """`days < 14` is WARNING; 14 itself falls through to SOON."""
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": 13, "ok": True}])
    out = buf.getvalue()
    assert "WARNING" in out
    assert "SOON" not in out


def test_print_cert_results_marks_zero_days_as_warning(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": 0, "ok": False}])
    out = buf.getvalue()
    assert "WARNING" in out
    assert "EXPIRED" not in out


def test_print_cert_results_marks_14_to_29_days_as_soon(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": 14, "ok": True}])
    out = buf.getvalue()
    assert "SOON" in out
    assert "WARNING" not in out


def test_print_cert_results_marks_30_days_or_more_as_ok(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": 30, "ok": True}])
    assert "OK" in buf.getvalue()


def test_print_cert_results_marks_negative_days_as_expired(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": -4, "ok": False}])
    assert "EXPIRED" in buf.getvalue()


def test_print_cert_results_marks_none_days_as_err(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results(
        "example.com",
        [
            {"port": 443, "days_left": None, "ok": False, "error": "connection refused"},
        ],
    )
    out = buf.getvalue()
    assert "ERR" in out
    assert "connection refused" in out


def test_print_cert_results_falls_back_to_dash_when_no_subject(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results("example.com", [{"port": 443, "days_left": 60, "ok": True}])
    assert "—" in buf.getvalue()


def test_print_cert_results_shows_one_row_per_result(monkeypatch):
    buf = _capture_console(monkeypatch, cert)
    cert.print_cert_results(
        "example.com",
        [
            {"port": 80, "days_left": 100},
            {"port": 443, "days_left": 50},
            {"port": 8443, "days_left": 5},
        ],
    )
    out = buf.getvalue()
    assert "80" in out and "443" in out and "8443" in out
