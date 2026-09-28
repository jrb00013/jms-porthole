"""Extra unit tests for porthole.scanner — banner-grab failure handling, the
default port set, and the two result renderers.

`socket.create_connection` and `scanner.check_port` are always patched, so no
real socket is ever opened and no real scan is performed.
"""

import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from porthole import scanner


@pytest.fixture
def console_buf(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(scanner, "console", Console(file=buf, width=200, no_color=True))
    return buf


# ── grab_banner ───────────────────────────────────────────────────────────────


def test_grab_banner_returns_empty_string_when_recv_fails():
    sock = MagicMock()
    sock.recv.side_effect = ConnectionResetError("peer reset")
    ctx = MagicMock()
    ctx.__enter__.return_value = sock
    with patch("socket.create_connection", return_value=ctx):
        assert scanner.grab_banner("10.0.0.1", 22) == ""


def test_grab_banner_returns_empty_string_when_recv_returns_no_data():
    sock = MagicMock()
    sock.recv.return_value = b""
    ctx = MagicMock()
    ctx.__enter__.return_value = sock
    with patch("socket.create_connection", return_value=ctx):
        assert scanner.grab_banner("10.0.0.1", 80) == ""


def test_grab_banner_strips_whitespace_and_truncates_to_eighty_characters():
    sock = MagicMock()
    sock.recv.return_value = b"  " + b"A" * 200 + b"\r\n"
    ctx = MagicMock()
    ctx.__enter__.return_value = sock
    with patch("socket.create_connection", return_value=ctx):
        banner = scanner.grab_banner("10.0.0.1", 22)

    assert banner == "A" * 80


def test_grab_banner_applies_the_timeout_to_the_socket_itself():
    sock = MagicMock()
    sock.recv.return_value = b"hi"
    ctx = MagicMock()
    ctx.__enter__.return_value = sock
    with patch("socket.create_connection", return_value=ctx) as conn:
        scanner.grab_banner("10.0.0.1", 22, timeout=3.5)

    assert conn.call_args.kwargs["timeout"] == 3.5
    sock.settimeout.assert_called_once_with(3.5)


def test_grab_banner_decodes_undecodable_bytes_without_raising():
    sock = MagicMock()
    sock.recv.return_value = b"\xff\xfe SSH-2.0"
    ctx = MagicMock()
    ctx.__enter__.return_value = sock
    with patch("socket.create_connection", return_value=ctx):
        assert "SSH-2.0" in scanner.grab_banner("10.0.0.1", 22)


# ── scan_ports ────────────────────────────────────────────────────────────────


def test_scan_ports_defaults_to_the_full_common_port_table():
    checked = []

    def fake_check(host, port, timeout=0.5):
        checked.append(port)
        return False

    with patch.object(scanner, "check_port", side_effect=fake_check):
        assert scanner.scan_ports("10.0.0.1") == {}

    assert sorted(checked) == sorted(scanner.COMMON_PORTS.keys())
    assert len(checked) == len(scanner.COMMON_PORTS)


def test_scan_ports_combines_service_name_with_the_grabbed_banner():
    with (
        patch.object(scanner, "check_port", side_effect=lambda h, p, t=0.5: p == 22),
        patch.object(scanner, "grab_banner", return_value="SSH-2.0-OpenSSH_9.6") as banner_mock,
    ):
        result = scanner.scan_ports("10.0.0.1", ports=[22, 80])

    assert result == {22: "SSH  SSH-2.0-OpenSSH_9.6"}
    banner_mock.assert_called_once_with("10.0.0.1", 22)


def test_scan_ports_labels_unknown_ports_as_unknown():
    with (
        patch.object(scanner, "check_port", side_effect=lambda h, p, t=0.5: p == 12345),
        patch.object(scanner, "grab_banner", return_value=""),
    ):
        result = scanner.scan_ports("10.0.0.1", ports=[12345])

    assert result == {12345: "unknown"}


def test_scan_ports_returns_results_sorted_by_port_number():
    with (
        patch.object(scanner, "check_port", side_effect=lambda h, p, t=0.5: True),
        patch.object(scanner, "grab_banner", return_value=""),
    ):
        result = scanner.scan_ports("10.0.0.1", ports=[8080, 22, 443, 80])

    assert list(result.keys()) == [22, 80, 443, 8080]


def test_scan_ports_returns_empty_dict_when_every_port_is_closed():
    with (
        patch.object(scanner, "check_port", return_value=False),
        patch.object(scanner, "grab_banner") as banner_mock,
    ):
        assert scanner.scan_ports("10.0.0.1", ports=[22, 80, 443]) == {}

    banner_mock.assert_not_called()


# ── port presets ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "preset,expected",
    [
        ("web", [80, 443, 8080, 8443, 8888]),
        ("db", [3306, 5432, 27017, 6379, 9200]),
        ("remote", [22, 23, 3389, 5900, 5901]),
        ("devops", [2375, 2376, 9090, 3000, 5601, 9200]),
    ],
    ids=["web", "db", "remote", "devops"],
)
def test_resolve_port_preset_returns_the_documented_port_list(preset, expected):
    assert scanner.resolve_port_preset(preset) == expected


def test_resolve_port_preset_all_covers_ports_one_through_one_024():
    ports = scanner.resolve_port_preset("all")

    assert ports[0] == 1
    assert ports[-1] == 1024
    assert len(ports) == 1024


@pytest.mark.parametrize("preset", ["", "WEB", "unknown", "ftp"])
def test_resolve_port_preset_returns_empty_list_for_anything_unrecognised(preset):
    assert scanner.resolve_port_preset(preset) == []


def test_resolve_port_preset_returns_a_copy_not_the_shared_list():
    first = scanner.resolve_port_preset("web")
    first.append(1)

    assert scanner.resolve_port_preset("web") == [80, 443, 8080, 8443, 8888]
    assert scanner.PORT_RANGE_PRESETS["web"] == [80, 443, 8080, 8443, 8888]


# ── print_scan_results ────────────────────────────────────────────────────────


def test_print_scan_results_reports_when_no_ports_are_open(console_buf):
    scanner.print_scan_results("10.0.0.1", {})

    out = console_buf.getvalue()
    assert "No open ports found on 10.0.0.1" in out
    assert "Open Ports" not in out


def test_print_scan_results_renders_port_service_and_banner_columns(console_buf):
    scanner.print_scan_results(
        "10.0.0.1", {22: "SSH  SSH-2.0-OpenSSH_9.6", 80: "HTTP  nginx/1.24.0"}
    )

    out = console_buf.getvalue()
    assert "Open Ports — 10.0.0.1" in out
    for header in ("Port", "Service", "Banner"):
        assert header in out
    assert "22" in out and "80" in out
    assert "SSH" in out and "HTTP" in out
    assert "SSH-2.0-OpenSSH_9.6" in out
    assert "nginx/1.24.0" in out


def test_print_scan_results_leaves_banner_blank_when_info_has_no_separator(console_buf):
    scanner.print_scan_results("10.0.0.1", {8080: "HTTP-Alt"})

    out = console_buf.getvalue()
    assert "8080" in out
    assert "HTTP-Alt" in out
    # Title uses an em-dash ("Open Ports — host"); the banner *cell* must stay blank.
    banner_cells = [line for line in out.splitlines() if "8080" in line and "HTTP-Alt" in line]
    assert banner_cells, "expected a table row for port 8080"
    after_service = banner_cells[0].split("HTTP-Alt", 1)[1]
    assert "—" not in after_service


def test_print_scan_results_renders_a_row_for_every_open_port(console_buf):
    scanner.print_scan_results("10.0.0.1", {22: "SSH", 80: "HTTP", 443: "HTTPS"})

    out = console_buf.getvalue()
    for port in ("22", "80", "443"):
        assert port in out
    for service in ("SSH", "HTTP", "HTTPS"):
        assert service in out


# ── print_network_results ─────────────────────────────────────────────────────


def test_print_network_results_titles_table_with_the_cidr(console_buf):
    scanner.print_network_results("192.168.1.0/24", ["192.168.1.1"])

    out = console_buf.getvalue().replace("\n", " ")
    assert "Live Hosts" in out
    assert "192.168.1.0/24" in out
    assert "IP Address" in out
    assert "Status" in out


def test_print_network_results_marks_every_live_host_online(console_buf):
    scanner.print_network_results("10.0.0.0/24", ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    out = console_buf.getvalue()
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        assert host in out
    assert out.count("● online") == 3


def test_print_network_results_summary_counts_live_hosts(console_buf):
    scanner.print_network_results("10.0.0.0/24", ["10.0.0.1", "10.0.0.2"])

    assert "2 host(s) online" in console_buf.getvalue()


def test_print_network_results_reports_zero_hosts_when_nothing_is_live(console_buf):
    scanner.print_network_results("10.0.0.0/24", [])

    out = console_buf.getvalue().replace("\n", " ")
    assert "Live Hosts" in out
    assert "10.0.0.0/24" in out
    assert "0 host(s) online" in out
    assert "● online" not in out


# ── scan_network / ping_host guards ───────────────────────────────────────────


def test_scan_network_treats_a_host_address_cidr_as_a_single_host_network():
    with patch.object(scanner, "ping_host", return_value=True):
        assert scanner.scan_network("10.0.0.5/32") == ["10.0.0.5"]


def test_scan_network_reports_the_invalid_cidr_message():
    with pytest.raises(ValueError, match="Invalid CIDR"):
        scanner.scan_network("999.0.0.0/24")


def test_scan_network_falls_back_to_all_hosts_for_a_wide_cidr_mask():
    with patch.object(scanner, "ping_host", side_effect=lambda h, timeout=1.0: h == "10.0.1.255"):
        assert scanner.scan_network("10.0.0.0/16") == ["10.0.1.255"]


def test_ping_host_stops_probing_after_the_first_open_port():
    checked = []

    def fake_check(host, port, timeout=0.5):
        checked.append(port)
        return port == 80

    with patch.object(scanner, "check_port", side_effect=fake_check):
        assert scanner.ping_host("10.0.0.1") is True

    assert checked == [22, 80]
    assert 443 not in checked
