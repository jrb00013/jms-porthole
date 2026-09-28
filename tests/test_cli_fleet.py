"""CLI-level tests for --hosts-file/--parallel fleet execution on scan,
spray, netmap, and procs ps — verifying they reuse the fleet.py
thread-pool pattern proven for health rather than only accepting a
single target."""

from click.testing import CliRunner

from porthole.cli import main


def _hosts_file(tmp_path, *hosts):
    p = tmp_path / "hosts.txt"
    p.write_text("\n".join(hosts) + "\n")
    return str(p)


def test_scan_hosts_file_runs_over_each_host(tmp_path, monkeypatch):
    calls = []

    def fake_scan_ports(host, ports, threads):
        calls.append(host)
        return {ports[0]: f"open on {host}"}

    monkeypatch.setattr("porthole.scanner.scan_ports", fake_scan_ports)
    monkeypatch.setattr("porthole.store.record_run", lambda *a, **k: None)

    hf = _hosts_file(tmp_path, "10.0.0.1", "10.0.0.2")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "unused", "--hosts-file", hf, "--ports", "22", "--json"])

    assert result.exit_code == 0, result.output
    assert sorted(calls) == ["10.0.0.1", "10.0.0.2"]
    assert "10.0.0.1" in result.output and "10.0.0.2" in result.output


def test_spray_hosts_file_merges_with_positional_hosts(tmp_path, monkeypatch):
    seen = {}

    def fake_spray_hosts(hosts, users, passwords, port, threads):
        seen["hosts"] = list(hosts)
        return [{"host": h, "username": "u", "password": "p", "success": False} for h in hosts]

    monkeypatch.setattr("porthole.spray.spray_hosts", fake_spray_hosts)
    monkeypatch.setattr("porthole.spray.print_spray_results", lambda *a, **k: None)

    hf = _hosts_file(tmp_path, "10.0.0.3")
    runner = CliRunner()
    result = runner.invoke(
        main, ["spray", "10.0.0.4", "--hosts-file", hf, "-u", "root", "-p", "toor"]
    )

    assert result.exit_code == 0, result.output
    assert set(seen["hosts"]) == {"10.0.0.3", "10.0.0.4"}


def test_spray_requires_hosts_or_hosts_file():
    runner = CliRunner()
    result = runner.invoke(main, ["spray", "-u", "root", "-p", "toor"])
    assert result.exit_code != 0


def test_netmap_hosts_file_runs_over_each_cidr(tmp_path, monkeypatch):
    calls = []

    def fake_map_network(cidr, resolve_dns=True, threads=50):
        calls.append(cidr)
        return [{"host": f"{cidr}-host"}]

    monkeypatch.setattr("porthole.netmap.map_network", fake_map_network)
    monkeypatch.setattr("porthole.store.record_run", lambda *a, **k: None)

    hf = _hosts_file(tmp_path, "10.0.0.0/30", "10.0.1.0/30")
    runner = CliRunner()
    result = runner.invoke(main, ["netmap", "--hosts-file", hf, "--json"])

    assert result.exit_code == 0, result.output
    assert sorted(calls) == ["10.0.0.0/30", "10.0.1.0/30"]


def test_netmap_requires_cidr_or_hosts_file():
    runner = CliRunner()
    result = runner.invoke(main, ["netmap"])
    assert result.exit_code != 0


def test_procs_ps_hosts_file_runs_over_each_host(tmp_path, monkeypatch):
    calls = []

    def fake_list_processes(host, username, password, sort_by="cpu", limit=20):
        calls.append(host)
        return [{"pid": 1, "cpu": 0.0, "mem": 0.0, "cmd": "init"}]

    monkeypatch.setattr("porthole.procs.list_processes", fake_list_processes)
    monkeypatch.setattr("porthole.procs.print_processes", lambda *a, **k: None)
    monkeypatch.setattr("porthole.cli.resolve_host", lambda h, u, p: (h, u, p))

    hf = _hosts_file(tmp_path, "10.0.0.5", "10.0.0.6")
    runner = CliRunner()
    result = runner.invoke(main, ["procs", "ps", "--hosts-file", hf, "-u", "root", "-p", "toor"])

    assert result.exit_code == 0, result.output
    assert sorted(calls) == ["10.0.0.5", "10.0.0.6"]


def test_procs_ps_requires_host_or_hosts_file(monkeypatch):
    monkeypatch.setattr("porthole.cli.resolve_host", lambda h, u, p: (h, u, p))
    runner = CliRunner()
    result = runner.invoke(main, ["procs", "ps", "-u", "root", "-p", "toor"])
    assert result.exit_code != 0
