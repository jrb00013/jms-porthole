"""Unit tests for porthole.fleet — parallel host execution helper."""
import pytest

from porthole import fleet


def test_hosts_from_file_ignores_blank_and_comments(tmp_path):
    p = tmp_path / "hosts.txt"
    p.write_text("10.0.0.1\n\n# a comment\n10.0.0.2\n  \n10.0.0.3\n")
    assert fleet.hosts_from_file(str(p)) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_run_over_hosts_calls_fn_per_host_and_preserves_order():
    hosts = ["a", "b", "c"]
    results = fleet.run_over_hosts(hosts, lambda h: h.upper(), parallel=2)
    assert list(results.keys()) == hosts
    assert results == {"a": "A", "b": "B", "c": "C"}


def test_run_over_hosts_empty_list():
    assert fleet.run_over_hosts([], lambda h: h) == {}


def test_run_over_hosts_captures_exceptions_per_host_without_aborting():
    def fn(h):
        if h == "bad":
            raise RuntimeError("boom")
        return "ok"

    results = fleet.run_over_hosts(["good", "bad", "good2"], fn, parallel=3)
    assert results["good"] == "ok"
    assert isinstance(results["bad"], RuntimeError)
    assert results["good2"] == "ok"
