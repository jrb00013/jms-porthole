"""Unit tests for porthole.scanner — no real network access."""
import socket
from unittest.mock import patch, MagicMock

import pytest

from porthole import scanner


def test_resolve_port_preset_known():
    assert scanner.resolve_port_preset("web") == [80, 443, 8080, 8443, 8888]


def test_resolve_port_preset_unknown_returns_empty():
    assert scanner.resolve_port_preset("nonexistent") == []


def test_common_ports_table_has_ssh_and_https():
    assert scanner.COMMON_PORTS[22] == "SSH"
    assert scanner.COMMON_PORTS[443] == "HTTPS"


def test_check_port_success():
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = MagicMock()
        assert scanner.check_port("10.0.0.1", 22) is True


def test_check_port_refused():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError):
        assert scanner.check_port("10.0.0.1", 22) is False


def test_check_port_timeout():
    with patch("socket.create_connection", side_effect=socket.timeout):
        assert scanner.check_port("10.0.0.1", 22) is False


def test_grab_banner_returns_text():
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.0\r\n"
    ctx = MagicMock()
    ctx.__enter__.return_value = mock_sock
    with patch("socket.create_connection", return_value=ctx):
        banner = scanner.grab_banner("10.0.0.1", 22)
    assert banner.startswith("SSH-2.0-OpenSSH")


def test_grab_banner_swallows_errors():
    with patch("socket.create_connection", side_effect=OSError):
        assert scanner.grab_banner("10.0.0.1", 22) == ""


def test_ping_host_true_when_any_port_open():
    with patch.object(scanner, "check_port", side_effect=[False, False, True, False]):
        assert scanner.ping_host("10.0.0.1") is True


def test_ping_host_false_when_all_closed():
    with patch.object(scanner, "check_port", return_value=False):
        assert scanner.ping_host("10.0.0.1") is False


def test_scan_ports_uses_default_common_ports_and_reports_open():
    def fake_check(host, port, timeout=0.5):
        return port in (22, 80)

    with patch.object(scanner, "check_port", side_effect=fake_check), \
         patch.object(scanner, "grab_banner", return_value=""):
        result = scanner.scan_ports("10.0.0.1", ports=[22, 80, 443])

    assert set(result.keys()) == {22, 80}
    assert result[22].startswith("SSH")
    assert result[80].startswith("HTTP")


def test_scan_network_rejects_bad_cidr():
    with pytest.raises(ValueError):
        scanner.scan_network("not-a-cidr")


def test_scan_network_returns_sorted_live_hosts():
    with patch.object(scanner, "ping_host", side_effect=lambda h, timeout=1.0: h.endswith(".2") or h.endswith(".5")):
        live = scanner.scan_network("192.168.50.0/29")
    assert live == sorted(live)
    for h in live:
        assert h.endswith(".2") or h.endswith(".5")
