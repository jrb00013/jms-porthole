"""Unit tests for porthole.harvest — SSHClient and test_connection are always faked."""

import threading
from concurrent.futures import ThreadPoolExecutor as RealExecutor

import pytest

from porthole import harvest

EXPECTED_COMMANDS = [
    "lsb_release -d 2>/dev/null | cut -d: -f2 | xargs || "
    "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'",
    "uname -r",
    "nproc",
    "free -h | awk '/^Mem:/{print $2}'",
    "uptime -p 2>/dev/null | sed 's/up //'",
    "who | wc -l",
    "ss -tlnp | awk 'NR>1{print $4}' | grep -oP ':\\K\\d+' | sort -n | tr '\\n' ',' | sed 's/,$//'",
]


class FakeSSH:
    """Records the commands harvest asks for and replays canned output."""

    instances = []
    connect_error = None
    outputs = {}

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.commands = []
        self.disconnected = False
        type(self).instances.append(self)

    def __enter__(self):
        if type(self).connect_error is not None:
            raise type(self).connect_error
        return self

    def __exit__(self, *_):
        self.disconnected = True
        return False

    def run_out(self, cmd):
        self.commands.append(cmd)
        return type(self).outputs.get(cmd, "out")


EMPTY_UNREACHABLE = {
    "host": "h",
    "status": "unreachable",
    "os": "",
    "kernel": "",
    "cpu": "",
    "ram": "",
    "uptime": "",
    "users": "",
    "open_ports": "",
}


class RecordingConsole:
    def __init__(self):
        self.printed = []
        self.cleared = 0

    def print(self, *args, **kwargs):
        self.printed.append(args[0] if args else None)

    def clear(self):
        self.cleared += 1


@pytest.fixture
def fake_ssh(monkeypatch):
    FakeSSH.instances = []
    FakeSSH.connect_error = None
    FakeSSH.outputs = {}
    monkeypatch.setattr(harvest, "SSHClient", FakeSSH)
    monkeypatch.setattr(harvest, "test_connection", lambda host: True)
    return FakeSSH


# --------------------------------------------------------------------------
# probe_host()
# --------------------------------------------------------------------------


def test_probe_host_collects_every_factoring_field_from_the_ssh_host(fake_ssh):
    fake_ssh.outputs = {
        "uname -r": "5.15.0-99-generic",
        "nproc": "8",
        "free -h | awk '/^Mem:/{print $2}'": "31Gi",
        "uptime -p 2>/dev/null | sed 's/up //'": "3 days, 4:11",
        "who | wc -l": "2",
        "ss -tlnp | awk 'NR>1{print $4}' | grep -oP ':\\K\\d+' | sort -n | tr '\\n' ',' | sed 's/,$//'": "22,80,443",
    }
    result = harvest.probe_host("10.0.0.5", "root", "pw")

    assert result["host"] == "10.0.0.5"
    assert result["status"] == "online"
    assert result["kernel"] == "5.15.0-99-generic"
    assert result["cpu"] == "8"
    assert result["ram"] == "31Gi"
    assert result["uptime"] == "3 days, 4:11"
    assert result["users"] == "2"
    assert result["open_ports"] == "22,80,443"


def test_probe_host_issues_the_exact_seven_commands_in_order(fake_ssh):
    harvest.probe_host("h", "u", "p")
    assert fake_ssh.instances[0].commands == EXPECTED_COMMANDS


def test_probe_host_connects_with_the_supplied_credentials(fake_ssh):
    harvest.probe_host("10.0.0.5", "deploy", "hunter2")
    instance = fake_ssh.instances[0]
    assert (instance.host, instance.username, instance.password) == (
        "10.0.0.5",
        "deploy",
        "hunter2",
    )


def test_probe_host_disconnects_the_ssh_client_when_done(fake_ssh):
    harvest.probe_host("h", "u", "p")
    assert fake_ssh.instances[0].disconnected is True


def test_probe_host_returns_unreachable_without_ssh_when_port_check_fails(monkeypatch, fake_ssh):
    monkeypatch.setattr(harvest, "test_connection", lambda host: False)
    result = harvest.probe_host("10.0.0.5", "u", "p")
    assert result == {
        "host": "10.0.0.5",
        "status": "unreachable",
        "os": "",
        "kernel": "",
        "cpu": "",
        "ram": "",
        "uptime": "",
        "users": "",
        "open_ports": "",
    }
    assert fake_ssh.instances == []


def test_probe_host_reports_auth_failed_when_the_ssh_connection_raises(fake_ssh):
    fake_ssh.connect_error = RuntimeError("Authentication failed.")
    result = harvest.probe_host("10.0.0.5", "root", "bad")
    assert result["status"] == "auth failed"
    assert result["host"] == "10.0.0.5"
    assert result["kernel"] == ""


# --------------------------------------------------------------------------
# harvest()
# --------------------------------------------------------------------------


def test_harvest_returns_one_result_per_host_sorted_by_host(monkeypatch, fake_ssh):
    results = harvest.harvest(["10.0.0.3", "10.0.0.1", "10.0.0.2"], "root", "pw")
    assert [r["host"] for r in results] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_harvest_probes_every_host_with_the_same_credentials(monkeypatch, fake_ssh):
    harvest.harvest(["a", "b", "c"], "deploy", "s3cret", threads=2)
    assert sorted((i.host, i.username, i.password) for i in fake_ssh.instances) == [
        ("a", "deploy", "s3cret"),
        ("b", "deploy", "s3cret"),
        ("c", "deploy", "s3cret"),
    ]


def test_harvest_requests_the_same_seven_commands_for_every_host(monkeypatch, fake_ssh):
    harvest.harvest(["a", "b"], "root", "pw")
    assert [i.commands for i in fake_ssh.instances] == [EXPECTED_COMMANDS, EXPECTED_COMMANDS]


def test_harvest_keeps_going_when_one_host_fails_to_authenticate(monkeypatch, fake_ssh):
    original_enter = FakeSSH.__enter__

    def flaky_enter(self):
        if self.host == "bad":
            raise RuntimeError("Authentication failed.")
        return original_enter(self)

    monkeypatch.setattr(FakeSSH, "__enter__", flaky_enter)

    results = harvest.harvest(["good1", "bad", "good2"], "root", "pw", threads=3)
    by_host = {r["host"]: r for r in results}
    assert by_host["bad"]["status"] == "auth failed"
    assert by_host["good1"]["status"] == "online"
    assert by_host["good2"]["status"] == "online"


def test_harvest_marks_hosts_that_fail_the_port_check_as_unreachable(monkeypatch, fake_ssh):
    monkeypatch.setattr(harvest, "test_connection", lambda host: host != "down")
    results = harvest.harvest(["up", "down"], "root", "pw")
    assert {r["host"]: r["status"] for r in results} == {"up": "online", "down": "unreachable"}


def test_harvest_returns_empty_list_for_no_hosts(monkeypatch, fake_ssh):
    assert harvest.harvest([], "root", "pw") == []


def test_harvest_passes_the_requested_thread_count_to_the_executor(monkeypatch, fake_ssh):
    seen = []
    real = RealExecutor

    def spy(max_workers=None):
        seen.append(max_workers)
        return real(max_workers=max_workers)

    monkeypatch.setattr(harvest, "ThreadPoolExecutor", spy)
    harvest.harvest(["a", "b", "c"], "root", "pw", threads=7)
    assert seen == [7]


def test_harvest_defaults_to_ten_workers(monkeypatch, fake_ssh):
    seen = []
    real = RealExecutor

    def spy(max_workers=None):
        seen.append(max_workers)
        return real(max_workers=max_workers)

    monkeypatch.setattr(harvest, "ThreadPoolExecutor", spy)
    harvest.harvest(["a"], "root", "pw")
    assert seen == [10]


def test_harvest_runs_at_most_the_requested_number_of_probes_at_once(monkeypatch):
    monkeypatch.setattr(harvest, "test_connection", lambda host: True)
    monkeypatch.setattr(harvest, "SSHClient", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(harvest, "run_health_checks", None, raising=False)

    barrier = threading.Barrier(3, timeout=5)
    entered = []
    lock = threading.Lock()

    def probe(host, username, password):
        with lock:
            entered.append(host)
        barrier.wait()  # only unblocks if 3 probes really run in parallel
        return {
            "host": host,
            "status": "online",
            "os": "",
            "kernel": "",
            "cpu": "",
            "ram": "",
            "uptime": "",
            "users": "",
            "open_ports": "",
        }

    monkeypatch.setattr(harvest, "probe_host", probe)

    results = harvest.harvest(["a", "b", "c"], "root", "pw", threads=3)

    assert sorted(entered) == ["a", "b", "c"]
    assert [r["host"] for r in results] == ["a", "b", "c"]


# --------------------------------------------------------------------------
# print_harvest_results()
# --------------------------------------------------------------------------


def test_print_harvest_results_renders_a_row_per_host(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)

    harvest.print_harvest_results(
        [
            {
                "host": "h1",
                "status": "online",
                "os": "Ubuntu 22.04.3 LTS",
                "cpu": "8",
                "ram": "31Gi",
                "uptime": "3 days",
                "users": "2",
                "open_ports": "22,443",
            },
        ]
    )

    table = console.printed[0]
    assert table.row_count == 1
    assert table.columns[0]._cells == ["h1"]
    assert "green" in table.columns[1]._cells[0]
    assert "online" in table.columns[1]._cells[0]
    assert table.columns[7]._cells[0] == "22,443"


def test_print_harvest_results_colours_unreachable_status_red(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    harvest.print_harvest_results([EMPTY_UNREACHABLE])
    table = console.printed[0]
    assert table.columns[1]._cells[0] == "[red]unreachable[/red]"


def test_print_harvest_results_colours_auth_failed_status_yellow(monkeypatch, fake_ssh):
    fake_ssh.connect_error = RuntimeError("nope")
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    harvest.print_harvest_results([harvest.probe_host("h", "u", "p")])
    assert console.printed[0].columns[1]._cells[0] == "[yellow]auth failed[/yellow]"


def test_print_harvest_results_substitutes_dash_for_missing_fields(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    harvest.print_harvest_results([EMPTY_UNREACHABLE])
    table = console.printed[0]
    assert table.columns[2]._cells[0] == "—"  # os
    assert table.columns[3]._cells[0] == "—"  # cpu
    assert table.columns[4]._cells[0] == "—"  # ram
    assert table.columns[5]._cells[0] == "—"  # uptime
    assert table.columns[6]._cells[0] == "—"  # users
    assert table.columns[7]._cells[0] == "—"  # open ports


def test_print_harvest_results_truncates_long_os_strings_to_30_chars(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    long_os = "D" * 60
    harvest.print_harvest_results(
        [{**harvest.probe_host("h", "u", "p"), "status": "online", "os": long_os}]
    )
    assert console.printed[0].columns[2]._cells[0] == "D" * 30


def test_print_harvest_results_prints_accessible_host_count(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    base = harvest.probe_host("h", "u", "p")
    online = {**base, "host": "h1", "status": "online"}
    offline = {**base, "host": "h2", "status": "unreachable"}
    harvest.print_harvest_results([online, offline])
    assert console.printed[-1] == "[bold]1/2 host(s) accessible[/bold]"


def test_print_harvest_results_with_no_results_reports_zero_of_zero(monkeypatch, fake_ssh):
    console = RecordingConsole()
    monkeypatch.setattr(harvest, "console", console)
    harvest.print_harvest_results([])
    assert console.printed[0].row_count == 0
    assert console.printed[-1] == "[bold]0/0 host(s) accessible[/bold]"
