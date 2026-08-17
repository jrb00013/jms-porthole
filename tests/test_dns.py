"""Unit tests for porthole.dns — parsing/shaping logic, no real DNS queries."""
import socket
from unittest.mock import patch, MagicMock

from porthole import dns as dns_mod


def test_lookup_a_returns_unique_ips():
    fake = [
        (socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
        (socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
        (socket.AF_INET, None, None, "", ("1.2.3.5", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=fake):
        ips = dns_mod.lookup_a("example.com")
    assert sorted(ips) == ["1.2.3.4", "1.2.3.5"]


def test_lookup_a_handles_gaierror():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        assert dns_mod.lookup_a("nope.invalid") == []


def test_lookup_aaaa_handles_gaierror():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        assert dns_mod.lookup_aaaa("nope.invalid") == []


def test_reverse_dns_success():
    with patch("socket.gethostbyaddr", return_value=("host.example.com", [], ["1.2.3.4"])):
        assert dns_mod.reverse_dns("1.2.3.4") == "host.example.com"


def test_reverse_dns_failure_returns_empty_string():
    with patch("socket.gethostbyaddr", side_effect=socket.herror):
        assert dns_mod.reverse_dns("1.2.3.4") == ""


def test_dig_uses_dig_when_available():
    fake_result = MagicMock(stdout="203.0.113.5\n")
    with patch("shutil.which", return_value="/usr/bin/dig"), \
         patch("subprocess.run", return_value=fake_result) as run_mock:
        out = dns_mod._dig("example.com", "A")
    assert out == "203.0.113.5"
    args = run_mock.call_args[0][0]
    assert args[0] == "dig"


def test_dig_returns_empty_when_no_tool_available():
    with patch("shutil.which", return_value=None):
        assert dns_mod._dig("example.com", "MX") == ""


def test_lookup_records_combines_a_and_dig_types():
    with patch.object(dns_mod, "lookup_a", return_value=["1.2.3.4"]), \
         patch.object(dns_mod, "lookup_aaaa", return_value=[]), \
         patch.object(dns_mod, "_dig", return_value="mail.example.com."):
        records = dns_mod.lookup_records("example.com", rtypes=["A", "AAAA", "MX"])

    assert records["A"] == ["1.2.3.4"]
    assert records["AAAA"] == []
    assert records["MX"] == ["mail.example.com."]


def test_enumerate_subdomains_only_returns_resolved():
    def fake_lookup_a(fqdn):
        return ["1.2.3.4"] if fqdn.startswith("www.") else []

    with patch.object(dns_mod, "lookup_a", side_effect=fake_lookup_a):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["www", "doesnotexist"])

    assert len(found) == 1
    assert found[0]["subdomain"] == "www.example.com"
    assert found[0]["ips"] == ["1.2.3.4"]


def test_enumerate_subdomains_empty_when_none_resolve():
    with patch.object(dns_mod, "lookup_a", return_value=[]):
        found = dns_mod.enumerate_subdomains("example.com", wordlist=["nope"])
    assert found == []
