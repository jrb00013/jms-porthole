"""Unit tests for porthole.procs — remote process/service commands, no real SSH."""

import io

import pytest
from rich.console import Console
from rich.table import Table

from porthole import procs


class FakeSSH:
    """Context-manager stand-in for porthole.ssh.SSHClient that records commands.

    Output is configured on the class (``FakeSSH.out/err/code``) so a test can set
    canned stdout for every connection the module under test opens.
    """

    out = ""
    err = ""
    code = 0
    instances = []

    def __init__(self, host, username, password=None, key_path=None, port=22, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.commands = []
        self.sudo_commands = []
        self.connected = self.disconnected = False
        FakeSSH.instances.append(self)

    def __enter__(self):
        self.connected = True
        return self

    def __exit__(self, *_):
        self.disconnected = True
        return False

    def run_out(self, cmd, timeout=30):
        self.commands.append(cmd)
        return self.out.strip()

    def run(self, cmd, timeout=30):
        self.commands.append(cmd)
        return self.out, self.err, self.code

    def run_sudo(self, cmd, timeout=30):
        self.sudo_commands.append(cmd)
        return self.out, self.err, self.code


def install(monkeypatch, cls=FakeSSH):
    monkeypatch.setattr(procs, "SSHClient", cls)
    return cls


@pytest.fixture(autouse=True)
def _reset_fake_ssh():
    FakeSSH.instances = []
    FakeSSH.out, FakeSSH.err, FakeSSH.code = "", "", 0
    yield
    FakeSSH.instances = []
    FakeSSH.out, FakeSSH.err, FakeSSH.code = "", "", 0


def make_console():
    buf = io.StringIO()
    return Console(file=buf, width=300, no_color=True), buf


def table_rows(table: Table) -> list[list[str]]:
    return [
        [str(table.columns[i]._cells[r]) for i in range(len(table.columns))]
        for r in range(len(table.rows))
    ]


SERVICES_RAW = (
    "ssh.service active running\n"
    "nginx.service active running\n"
    "cron.service failed scheduled\n"
    "bluetooth.service inactive dead"
)


def test_list_services_parses_name_state_and_remaining_words_as_description(monkeypatch):
    cls = install(monkeypatch)
    cls.out = SERVICES_RAW

    services = procs.list_services("10.0.4.21", "root", "pw")

    assert services == [
        {"name": "ssh.service", "state": "active", "description": "running"},
        {"name": "nginx.service", "state": "active", "description": "running"},
        {"name": "cron.service", "state": "failed", "description": "scheduled"},
        {"name": "bluetooth.service", "state": "inactive", "description": "dead"},
    ]


def test_list_services_joins_every_token_after_the_state_into_description(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "ssh.service active running OpenSSH daemon started"

    services = procs.list_services("10.0.4.21", "root", "pw")

    assert services[0]["description"] == "running OpenSSH daemon started"


def test_list_services_with_only_name_and_state_leaves_description_empty(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "ssh.service active"
    services = procs.list_services("10.0.4.21", "root", "pw")
    assert services == [{"name": "ssh.service", "state": "active", "description": ""}]


def test_list_services_runs_systemctl_list_units_with_awk_field_selection(monkeypatch):
    cls = install(monkeypatch)
    cls.out = SERVICES_RAW

    procs.list_services("10.0.4.21", "root", "pw")

    assert len(cls.instances[0].commands) == 1
    cmd = cls.instances[0].commands[0]
    assert cmd.startswith("systemctl list-units --type=service --no-pager --no-legend")
    assert "awk '{print $1, $3, $4}'" in cmd
    assert "2>/dev/null" in cmd


def test_list_services_connects_and_disconnects_with_given_credentials(monkeypatch):
    cls = install(monkeypatch)
    cls.out = SERVICES_RAW

    procs.list_services("10.0.4.21", "deploy", "hunter2")

    client = cls.instances[0]
    assert (client.host, client.username, client.password) == ("10.0.4.21", "deploy", "hunter2")
    assert client.connected is True
    assert client.disconnected is True


def test_list_services_filters_by_state(monkeypatch):
    cls = install(monkeypatch)
    cls.out = SERVICES_RAW

    services = procs.list_services("10.0.4.21", "root", "pw", filter_state="failed")

    assert [s["name"] for s in services] == ["cron.service"]
    assert services[0]["state"] == "failed"


def test_list_services_filter_matching_nothing_returns_empty_list(monkeypatch):
    cls = install(monkeypatch)
    cls.out = SERVICES_RAW
    assert procs.list_services("10.0.4.21", "root", "pw", filter_state="reloading") == []


def test_list_services_skips_blank_and_single_token_lines(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "ssh.service loaded active running OpenSSH\n\norphan.service\ncron.service loaded failed Cron daemon"

    services = procs.list_services("10.0.4.21", "root", "pw")

    assert [s["name"] for s in services] == ["ssh.service", "cron.service"]


def test_list_services_with_no_units_returns_empty_list(monkeypatch):
    cls = install(monkeypatch)
    cls.out = ""
    assert procs.list_services("10.0.4.21", "root", "pw") == []


PROCESSES_RAW = "root|1|0.0|0.1|systemd\nwww-data|812|3.4|2.1|nginx:\ndeploy|2201|0.2|0.9|bash"


def test_list_processes_parses_pipe_delimited_fields_into_dicts(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW

    result = procs.list_processes("10.0.4.21", "root", "pw")

    assert result == [
        {"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.1", "command": "systemd"},
        {"user": "www-data", "pid": "812", "cpu": "3.4", "mem": "2.1", "command": "nginx:"},
        {"user": "deploy", "pid": "2201", "cpu": "0.2", "mem": "0.9", "command": "bash"},
    ]


def test_list_processes_command_field_is_only_the_eleventh_ps_field(monkeypatch):
    cls = install(monkeypatch)
    # awk prints $11, so only the first whitespace-delimited token of the command
    # ever reaches the parsed record.
    cls.out = "www-data|812|3.4|2.1|nginx:|"

    result = procs.list_processes("10.0.4.21", "root", "pw")

    assert result[0]["command"] == "nginx:"
    assert result[0]["user"] == "www-data"
    assert result[0]["pid"] == "812"


def test_list_processes_sorts_by_cpu_column_by_default(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW

    procs.list_processes("10.0.4.21", "root", "pw")
    assert "--sort=-3" in cls.instances[0].commands[0]


def test_list_processes_sort_by_mem_uses_column_four(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW
    procs.list_processes("10.0.4.21", "root", "pw", sort_by="mem")
    assert "--sort=-4" in cls.instances[0].commands[0]


def test_list_processes_sort_by_pid_uses_column_one(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW
    procs.list_processes("10.0.4.21", "root", "pw", sort_by="pid")
    assert "--sort=-1" in cls.instances[0].commands[0]


def test_list_processes_unknown_sort_key_falls_back_to_cpu_column(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW
    procs.list_processes("10.0.4.21", "root", "pw", sort_by="bogus")
    assert "--sort=-3" in cls.instances[0].commands[0]


def test_list_processes_limit_controls_awk_row_range(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW
    procs.list_processes("10.0.4.21", "root", "pw", limit=5)
    assert "NR>1 && NR<=6" in cls.instances[0].commands[0]


def test_list_processes_default_limit_is_twenty_rows(monkeypatch):
    cls = install(monkeypatch)
    cls.out = PROCESSES_RAW
    procs.list_processes("10.0.4.21", "root", "pw")
    assert "NR>1 && NR<=21" in cls.instances[0].commands[0]


def test_list_processes_skips_lines_with_too_few_fields(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "root|1|0.0|0.1|systemd\nbroken|2|3.4\n\nroot|2|0.0|0.1|bash"

    result = procs.list_processes("10.0.4.21", "root", "pw")

    assert [p["pid"] for p in result] == ["1", "2"]


def test_list_processes_keeps_extra_fields_beyond_the_five_mapped(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "root|1|0.0|0.1|bash|--login|pts/0"

    result = procs.list_processes("10.0.4.21", "root", "pw")

    assert result == [{"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.1", "command": "bash"}]


def test_list_processes_with_no_processes_returns_empty_list(monkeypatch):
    cls = install(monkeypatch)
    cls.out = ""
    assert procs.list_processes("10.0.4.21", "root", "pw") == []


@pytest.mark.parametrize("action", ["start", "stop", "restart", "status", "enable", "disable"])
def test_service_action_accepts_every_allowed_action(monkeypatch, action):
    cls = install(monkeypatch)
    cls.out = "job done"

    ok, msg = procs.service_action("10.0.4.21", "root", "pw", "nginx.service", action)

    assert ok is True
    assert msg == "job done"
    assert cls.instances[0].sudo_commands == [f"systemctl {action} nginx.service"]


def test_service_action_rejects_unknown_action_without_connecting(monkeypatch):
    cls = install(monkeypatch)

    with pytest.raises(ValueError, match="Unknown action: reboot"):
        procs.service_action("10.0.4.21", "root", "pw", "nginx.service", "reboot")

    assert cls.instances == []


def test_service_action_rejects_empty_action_without_connecting(monkeypatch):
    cls = install(monkeypatch)
    with pytest.raises(ValueError):
        procs.service_action("10.0.4.21", "root", "pw", "nginx.service", "")
    assert cls.instances == []


def test_service_action_returns_false_and_stderr_message_on_failure(monkeypatch):
    cls = install(monkeypatch)
    cls.out, cls.err, cls.code = "", "Failed to start nginx.service: unit not found", 1

    ok, msg = procs.service_action("10.0.4.21", "root", "pw", "nginx.service", "start")

    assert ok is False
    assert msg == "Failed to start nginx.service: unit not found"


def test_service_action_prefers_stdout_over_stderr_when_both_present(monkeypatch):
    cls = install(monkeypatch)
    cls.out, cls.err, cls.code = "nginx restarted", "warning: deprecated unit file", 0

    ok, msg = procs.service_action("10.0.4.21", "root", "pw", "nginx.service", "restart")

    assert ok is True
    assert msg == "nginx restarted"


def test_service_action_uses_sudo_wrapper_not_plain_run(monkeypatch):
    cls = install(monkeypatch)
    procs.service_action("10.0.4.21", "root", "pw", "cron.service", "status")
    client = cls.instances[0]
    assert client.sudo_commands == ["systemctl status cron.service"]
    assert client.commands == []


def test_kill_process_builds_kill_command_with_signal_and_pid(monkeypatch):
    cls = install(monkeypatch)
    cls.out = "Terminated"

    ok, msg = procs.kill_process("10.0.4.21", "root", "pw", 4242, signal="KILL")

    assert ok is True
    assert msg == "Terminated"
    assert cls.instances[0].commands == ["kill -KILL 4242"]


def test_kill_process_defaults_to_term_signal(monkeypatch):
    cls = install(monkeypatch)
    procs.kill_process("10.0.4.21", "root", "pw", 1)
    assert cls.instances[0].commands == ["kill -TERM 1"]


def test_kill_process_returns_false_and_stderr_when_kill_fails(monkeypatch):
    cls = install(monkeypatch)
    cls.out, cls.err, cls.code = "", "kill: (99999) - No such process", 1

    ok, msg = procs.kill_process("10.0.4.21", "root", "pw", 99999)

    assert ok is False
    assert msg == "kill: (99999) - No such process"


def test_kill_process_does_not_use_sudo(monkeypatch):
    cls = install(monkeypatch)
    procs.kill_process("10.0.4.21", "root", "pw", 7)
    assert cls.instances[0].sudo_commands == []


def test_print_services_renders_name_state_and_description_columns(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(procs, "console", console)
    procs.print_services(
        "10.0.4.21",
        [
            {"name": "ssh.service", "state": "active", "description": "OpenSSH"},
            {"name": "cron.service", "state": "failed", "description": "Cron daemon"},
        ],
    )
    out = buf.getvalue()
    assert "Services — 10.0.4.21" in out
    assert "ssh.service" in out
    assert "OpenSSH" in out
    assert "active" in out
    assert "failed" in out


def test_print_services_colors_known_states_and_defaults_others_to_white(monkeypatch):
    captured = []

    class CapturingConsole:
        def print(self, obj):
            captured.append(obj)

    monkeypatch.setattr(procs, "console", CapturingConsole())
    procs.print_services(
        "h",
        [
            {"name": "a", "state": "active", "description": ""},
            {"name": "b", "state": "failed", "description": ""},
            {"name": "c", "state": "inactive", "description": ""},
            {"name": "d", "state": "activating", "description": ""},
        ],
    )
    table = captured[0]
    assert isinstance(table, Table)
    assert [c.header for c in table.columns] == ["Service", "State", "Description"]
    states = [row[1] for row in table_rows(table)]
    assert states == [
        "[green]active[/green]",
        "[red]failed[/red]",
        "[dim]inactive[/dim]",
        "[white]activating[/white]",
    ]


def test_print_services_uses_blank_description_when_key_missing(monkeypatch):
    captured = []
    monkeypatch.setattr(
        procs, "console", type("C", (), {"print": lambda self, o: captured.append(o)})()
    )
    procs.print_services("h", [{"name": "a", "state": "active"}])
    assert table_rows(captured[0])[0][2] == ""


def test_print_processes_renders_pid_user_cpu_mem_and_command(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(procs, "console", console)
    procs.print_processes(
        "10.0.4.21",
        [
            {"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.1", "command": "systemd"},
            {"user": "www-data", "pid": "812", "cpu": "3.4", "mem": "2.1", "command": "nginx"},
        ],
    )
    out = buf.getvalue()
    assert "Processes — 10.0.4.21" in out
    assert "systemd" in out
    assert "www-data" in out
    assert "3.4" in out
    assert "nginx" in out


def test_print_processes_truncates_long_command_to_fifty_chars(monkeypatch):
    captured = []
    monkeypatch.setattr(
        procs, "console", type("C", (), {"print": lambda self, o: captured.append(o)})()
    )
    long_cmd = "x" * 70
    procs.print_processes(
        "h", [{"user": "u", "pid": "9", "cpu": "1", "mem": "2", "command": long_cmd}]
    )
    rows = table_rows(captured[0])
    assert rows[0][4] == "x" * 50
    assert rows[0][0] == "9"


def test_print_processes_column_headers_and_alignment(monkeypatch):
    captured = []
    monkeypatch.setattr(
        procs, "console", type("C", (), {"print": lambda self, o: captured.append(o)})()
    )
    procs.print_processes("h", [])
    table = captured[0]
    assert [c.header for c in table.columns] == ["PID", "User", "CPU%", "MEM%", "Command"]
    assert [c.justify for c in table.columns] == ["right", "left", "right", "right", "left"]
    assert table.rows == []
