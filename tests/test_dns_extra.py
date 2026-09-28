"""Extra unit tests for porthole.dns — dig/host tool fallback parsing and the
result renderers.

`subprocess.run` and `shutil.which` are always patched, so no `dig`/`host`
binary is executed and no real DNS query is ever issued. `socket.getaddrinfo`
is patched wherever the A/AAAA code path is reached.
"""

import socket
import subprocess
from unittest.mock import patch

import pytest
from rich.console import Console

from porthole import dns as dns_mod


@pytest.fixture
def console_buf(monkeypatch):
    import io

    buf = io.StringIO()
    monkeypatch.setattr(dns_mod, "console", Console(file=buf, width=200, no_color=True))
    return buf


def _completed(stdout):
    return subprocess.CompletedProcess(args=["dig"], returncode=0, stdout=stdout, stderr="")


def _which(mapping):
    return lambda tool: mapping.get(tool)


# ── _dig tool selection and failure handling ──────────────────────────────────


def test_dig_falls_through_to_host_when_dig_binary_is_missing():
    host_out = "mail.example.com.\n"
    with (
        patch("shutil.which", _which({"host": "/usr/bin/host"})),
        patch("subprocess.run", return_value=_completed(host_out)) as run_mock,
    ):
        assert dns_mod._dig("example.com", "MX") == "mail.example.com."

    assert [call[0][0][0] for call in run_mock.call_args_list] == ["host"]


def test_dig_returns_empty_string_when_dig_raises_filenotfound():
    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig"})),
        patch("subprocess.run", side_effect=FileNotFoundError("gone")) as run_mock,
    ):
        assert dns_mod._dig("example.com", "A") == ""

    assert run_mock.call_count == 1, "host fallback must be skipped when 'host' is absent"


def test_dig_falls_through_to_host_when_dig_times_out():
    outputs = [
        subprocess.TimeoutExpired(cmd="dig", timeout=10),
        _completed("ns1.example.com.\n"),
    ]

    def fake_run(*args, **kwargs):
        result = outputs.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig", "host": "/usr/bin/host"})),
        patch("subprocess.run", side_effect=fake_run) as run_mock,
    ):
        assert dns_mod._dig("example.com", "NS") == "ns1.example.com."

    dig_cmd = run_mock.call_args_list[0][0][0]
    host_cmd = run_mock.call_args_list[1][0][0]
    assert dig_cmd == ["dig", "+short", "example.com", "NS"]
    assert host_cmd == ["host", "-t", "NS", "example.com"]


def test_dig_returns_empty_string_when_both_dig_and_host_time_out():
    def always_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="dig", timeout=10)

    with (
        patch("shutil.which", _which({"dig": "/d", "host": "/h"})),
        patch("subprocess.run", side_effect=always_timeout) as run_mock,
    ):
        assert dns_mod._dig("example.com", "TXT") == ""

    assert run_mock.call_count == 2


def test_dig_passes_a_ten_second_timeout_and_captures_text():
    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig"})),
        patch("subprocess.run", return_value=_completed("  1.2.3.4  \n")) as run_mock,
    ):
        assert dns_mod._dig("example.com", "A") == "1.2.3.4"

    kwargs = run_mock.call_args.kwargs
    assert kwargs["timeout"] == 10
    assert kwargs["text"] is True
    assert kwargs["capture_output"] is True


# ── record parsing from real dig output ───────────────────────────────────────


def _records_with_dig_stdout(stdout_by_type, rtypes, a_records=None, aaaa_records=None):
    def fake_run(cmd, **kwargs):
        rtype = cmd[3]
        return _completed(stdout_by_type.get(rtype, ""))

    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig"})),
        patch("subprocess.run", side_effect=fake_run),
        patch.object(dns_mod, "lookup_a", return_value=a_records if a_records is not None else []),
        patch.object(dns_mod, "lookup_aaaa", return_value=aaaa_records or []),
    ):
        return dns_mod.lookup_records("example.com", rtypes=rtypes)


def test_lookup_records_parses_multiple_mx_exchange_records():
    dig_out = "10 mail1.example.com.\n20 mail2.example.com.\n"

    records = _records_with_dig_stdout({"MX": dig_out}, ["MX"])

    assert records == {"MX": ["10 mail1.example.com.", "20 mail2.example.com."]}


def test_lookup_records_parses_quoted_txt_strings_intact():
    dig_out = '"v=spf1 include:_spf.example.com -all"\n"google-site-verification=abc123"\n'

    records = _records_with_dig_stdout({"TXT": dig_out}, ["TXT"])

    assert records["TXT"] == [
        '"v=spf1 include:_spf.example.com -all"',
        '"google-site-verification=abc123"',
    ]


def test_lookup_records_parses_ns_and_soa_records():
    dig_out = {
        "NS": "ns1.example.com.\nns2.example.com.\n",
        "SOA": "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600\n",
    }

    records = _records_with_dig_stdout(dig_out, ["NS", "SOA"])

    assert records["NS"] == ["ns1.example.com.", "ns2.example.com."]
    assert records["SOA"] == [
        "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600"
    ]


def test_lookup_records_parses_a_and_aaaa_via_getaddrinfo_not_dig():
    def fake_getaddrinfo(host, port, family):
        if family == socket.AF_INET:
            return [(socket.AF_INET, None, None, "", ("203.0.113.5", 0))]
        return [(socket.AF_INET6, None, None, "", ("2001:db8::1", 0, 0, 0))]

    with (
        patch("shutil.which", _which({})),
        patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
    ):
        records = dns_mod.lookup_records("example.com", rtypes=["A", "AAAA"])

    assert records == {"A": ["203.0.113.5"], "AAAA": ["2001:db8::1"]}


def test_lookup_records_omits_record_types_with_no_dig_output():
    """NXDOMAIN / empty answer: `dig +short` prints nothing, so the key is dropped."""
    records = _records_with_dig_stdout({"MX": "", "TXT": "\n\n"}, ["MX", "TXT"])

    assert records == {}


def test_lookup_records_keeps_aa_but_omits_dig_types_for_a_fully_empty_domain():
    records = _records_with_dig_stdout({}, ["A", "AAAA", "CNAME"])

    assert records == {"A": [], "AAAA": []}


def test_lookup_records_drops_blank_lines_from_dig_output():
    dig_out = "ns1.example.com.\n   \n\nns2.example.com.\n"

    records = _records_with_dig_stdout({"NS": dig_out}, ["NS"])

    assert records["NS"] == ["ns1.example.com.", "ns2.example.com."]


def test_lookup_records_preserves_malformed_dig_output_lines_verbatim():
    """Lines the parser cannot interpret are passed through unchanged, not dropped."""
    dig_out = "!! not a record line !!\nns1.example.com.\n"

    records = _records_with_dig_stdout({"NS": dig_out}, ["NS"])

    assert records["NS"] == ["!! not a record line !!", "ns1.example.com."]


def test_lookup_records_defaults_to_the_full_record_type_set():
    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig"})),
        patch("subprocess.run", return_value=_completed("ns1.example.com.\n")),
        patch.object(dns_mod, "lookup_a", return_value=["1.2.3.4"]) as a_mock,
        patch.object(dns_mod, "lookup_aaaa", return_value=["2001:db8::1"]) as aaaa_mock,
    ):
        records = dns_mod.lookup_records("example.com")

    a_mock.assert_called_once_with("example.com")
    aaaa_mock.assert_called_once_with("example.com")
    assert set(records) == {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}


def test_lookup_records_does_not_call_dig_for_a_and_aaaa_types():
    def explode(*args, **kwargs):
        raise AssertionError("_dig must not be used for A/AAAA lookups")

    with (
        patch("shutil.which", _which({"dig": "/usr/bin/dig"})),
        patch("subprocess.run", side_effect=explode),
        patch.object(dns_mod, "lookup_a", return_value=["1.2.3.4"]),
        patch.object(dns_mod, "lookup_aaaa", return_value=[]),
    ):
        assert dns_mod.lookup_records("example.com", rtypes=["A", "AAAA"]) == {
            "A": ["1.2.3.4"],
            "AAAA": [],
        }


# ── subdomain enumeration ─────────────────────────────────────────────────────


def test_enumerate_subdomains_defaults_to_the_common_wordlist():
    seen = []

    def fake_lookup_a(fqdn):
        seen.append(fqdn)
        return []

    with patch.object(dns_mod, "lookup_a", side_effect=fake_lookup_a):
        assert dns_mod.enumerate_subdomains("example.com") == []

    assert seen == [f"{sub}.example.com" for sub in dns_mod.COMMON_SUBDOMAINS]
    assert "www.example.com" in seen


def test_enumerate_subdomains_qualifies_bare_labels_with_the_domain():
    with patch.object(dns_mod, "lookup_a", side_effect=lambda fqdn: ["1.2.3.4"]):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["api", "vpn"])

    assert [f["subdomain"] for f in found] == ["api.example.com", "vpn.example.com"]
    assert all(f["ips"] == ["1.2.3.4"] for f in found)


def test_enumerate_subdomains_carries_every_resolved_ip_through():
    with patch.object(dns_mod, "lookup_a", return_value=["1.2.3.4", "5.6.7.8"]):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["www"])

    assert found == [{"subdomain": "www.example.com", "ips": ["1.2.3.4", "5.6.7.8"]}]


def test_enumerate_subdomains_filters_out_unresolved_labels():
    def fake_lookup_a(fqdn):
        return ["1.2.3.4"] if fqdn == "api.example.com" else []

    with patch.object(dns_mod, "lookup_a", side_effect=fake_lookup_a):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["api", "nope", "gone"])

    assert [f["subdomain"] for f in found] == ["api.example.com"]


def test_enumerate_subdomains_does_not_deduplicate_a_repeated_wordlist_entry():
    """Pins current behaviour: results are per-wordlist-entry, so repeats are duplicated."""
    with patch.object(dns_mod, "lookup_a", return_value=["1.2.3.4"]):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["www", "www"])

    assert found == [
        {"subdomain": "www.example.com", "ips": ["1.2.3.4"]},
        {"subdomain": "www.example.com", "ips": ["1.2.3.4"]},
    ]


# ── renderers ─────────────────────────────────────────────────────────────────


def test_print_dns_results_renders_one_row_per_value_labelling_only_the_first(console_buf):
    dns_mod.print_dns_results(
        "example.com", {"MX": ["10 mail1.example.com.", "20 mail2.example.com."]}
    )

    out = console_buf.getvalue()
    assert "DNS Records — example.com" in out
    assert "MX" in out
    assert "10 mail1.example.com." in out
    assert "20 mail2.example.com." in out
    assert out.count("MX") == 1, "continuation rows must have a blank type cell"


def test_print_dns_results_shows_dash_placeholder_for_empty_record_sets(console_buf):
    dns_mod.print_dns_results("example.com", {"A": [], "MX": ["10 mail.example.com."]})

    out = console_buf.getvalue()
    assert "—" in out
    assert "A" in out
    assert "10 mail.example.com." in out


def test_print_dns_results_renders_all_record_types(console_buf):
    dns_mod.print_dns_results(
        "example.com", {"A": ["1.2.3.4"], "NS": ["ns1.example.com."], "TXT": ['"hello"']}
    )

    out = console_buf.getvalue()
    for token in ("A", "1.2.3.4", "NS", "ns1.example.com.", "TXT", '"hello"'):
        assert token in out


def test_print_subdomain_results_reports_when_nothing_was_found(console_buf):
    dns_mod.print_subdomain_results("example.com", [])

    out = console_buf.getvalue()
    assert "No subdomains found for example.com" in out
    assert "Subdomains —" not in out


def test_print_subdomain_results_renders_fqdn_and_comma_joined_ips(console_buf):
    dns_mod.print_subdomain_results(
        "example.com",
        [
            {"subdomain": "www.example.com", "ips": ["1.2.3.4"]},
            {"subdomain": "mail.example.com", "ips": ["5.6.7.8", "9.10.11.12"]},
        ],
    )

    out = console_buf.getvalue()
    assert "Subdomains — example.com (2 found)" in out
    assert "www.example.com" in out
    assert "mail.example.com" in out
    assert "1.2.3.4" in out
    assert "5.6.7.8, 9.10.11.12" in out
