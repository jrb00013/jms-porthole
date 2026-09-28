"""Unit tests for porthole.monitor — stat parsing, bar formatting, and the live loop.

No real SSH and no real sleeps: the SSH client, Live, console and time.sleep are
all replaced, and the loop is terminated by raising KeyboardInterrupt.
"""

import io
import re

import pytest
from rich.console import Console, Group
from rich.panel import Panel

from porthole import monitor


class FakeSSH:
    """Records probe commands and returns canned stdout keyed by command substring."""

    def __init__(self, responses=None, default=""):
        self.responses = responses or {}
        self.default = default
        self.commands = []
        self.instances = []
        self.connected = False
        self.disconnected = False

    def __enter__(self):
        self.connected = True
        return self

    def __exit__(self, *_):
        self.disconnected = True
        return False

    def disconnect(self):
        self.disconnected = True

    def run_out(self, cmd, timeout=30):
        self.commands.append(cmd)
        for needle, out in self.responses.items():
            if needle in cmd:
                return out.strip()
        return self.default

    def run(self, cmd, timeout=30):
        return self.run_out(cmd), "", 0


STATS_RESPONSES = {
    "top -bn1": "12.5",
    "free -m": "16384 8192 8192",
    "df -h /": "98G 45G 44G 50%",
    "loadavg": "0.52 0.41 0.38",
    "uptime": "up 12 days, 4 hours",
    "ps aux": "root 1.2 0.5 /sbin/init\nwww-data 3.4 2.1 nginx\ndeploy 0.0 0.1 bash",
    "ss -tn": "7",
    "who | wc -l": "2",
}


def make_console():
    buf = io.StringIO()
    return Console(file=buf, width=200, no_color=True), buf


def make_client(responses=None, default=""):
    created = []

    class Recording(FakeSSH):
        def __init__(self, host, username, password=None, key_path=None, port=22, timeout=10):
            super().__init__(responses, default)
            self.host = host
            self.username = username
            self.password = password
            created.append(self)

    return Recording, created


def test_get_system_stats_parses_cpu_percent_as_float():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    assert stats["cpu"] == 12.5
    assert isinstance(stats["cpu"], float)


def test_get_system_stats_converts_comma_decimal_cpu_to_float():
    responses = dict(STATS_RESPONSES, **{"top -bn1": "7,25"})
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["cpu"] == 7.25


def test_get_system_stats_defaults_cpu_to_zero_when_probe_is_empty():
    responses = dict(STATS_RESPONSES)
    del responses["top -bn1"]
    responses["top -bn1"] = ""
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["cpu"] == 0.0


def test_get_system_stats_parses_memory_totals_used_and_free_in_mb():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    assert stats["mem_total"] == 16384
    assert stats["mem_used"] == 8192
    assert stats["mem_free"] == 8192


def test_get_system_stats_sets_memory_to_zero_when_free_output_is_empty():
    responses = dict(STATS_RESPONSES, **{"free -m": ""})
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["mem_total"] == 0
    assert stats["mem_used"] == 0
    assert stats["mem_free"] == 0


def test_get_system_stats_keeps_disk_fields_as_strings_including_percent():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    assert stats["disk_total"] == "98G"
    assert stats["disk_used"] == "45G"
    assert stats["disk_free"] == "44G"
    assert stats["disk_pct"] == "50%"


def test_get_system_stats_uses_question_marks_when_df_output_is_empty():
    responses = dict(STATS_RESPONSES, **{"df -h /": ""})
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["disk_total"] == "?"
    assert stats["disk_used"] == "?"
    assert stats["disk_free"] == "?"
    assert stats["disk_pct"] == "?"


def test_get_system_stats_captures_load_uptime_connections_and_users():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    assert stats["load"] == "0.52 0.41 0.38"
    assert stats["uptime"] == "up 12 days, 4 hours"
    assert stats["connections"] == "7"
    assert stats["users"] == "2"


def test_get_system_stats_splits_process_lines_into_field_lists():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    assert stats["procs"] == [
        ["root", "1.2", "0.5", "/sbin/init"],
        ["www-data", "3.4", "2.1", "nginx"],
        ["deploy", "0.0", "0.1", "bash"],
    ]


def test_get_system_stats_drops_interior_blank_process_lines():
    responses = dict(
        STATS_RESPONSES, **{"ps aux": "root 1.2 0.5 /sbin/init\n\nnginx 0.1 0.1 nginx"}
    )
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["procs"] == [
        ["root", "1.2", "0.5", "/sbin/init"],
        ["nginx", "0.1", "0.1", "nginx"],
    ]


def test_get_system_stats_keeps_whitespace_only_process_line_as_empty_entry():
    """Whitespace-only lines survive as [] — only truly empty lines are filtered."""
    responses = dict(STATS_RESPONSES, **{"ps aux": "root 1.2 0.5 init\n   \nnginx 0.1 0.1 nginx"})
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["procs"] == [["root", "1.2", "0.5", "init"], [], ["nginx", "0.1", "0.1", "nginx"]]


def test_get_system_stats_returns_empty_process_list_when_ps_is_empty():
    responses = dict(STATS_RESPONSES, **{"ps aux": ""})
    stats = monitor.get_system_stats(FakeSSH(responses))
    assert stats["procs"] == []


def test_get_system_stats_issues_expected_probe_commands():
    ssh = FakeSSH(STATS_RESPONSES)
    monitor.get_system_stats(ssh)
    assert ssh.commands[0] == "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
    assert "free -m | awk '/^Mem:/{print $2, $3, $4}'" in ssh.commands
    assert "df -h / | awk 'NR==2{print $2, $3, $4, $5}'" in ssh.commands
    assert "cat /proc/loadavg | awk '{print $1, $2, $3}'" in ssh.commands
    assert "uptime -p 2>/dev/null || uptime" in ssh.commands
    assert "ss -tn | grep ESTAB | wc -l" in ssh.commands
    assert "who | wc -l" in ssh.commands


def test_get_system_stats_limits_process_probe_to_seven_rows():
    ssh = FakeSSH(STATS_RESPONSES)
    monitor.get_system_stats(ssh)
    proc_cmd = [c for c in ssh.commands if c.startswith("ps aux")][0]
    assert "NR>1 && NR<=8" in proc_cmd
    assert "$1, $3, $4, $11" in proc_cmd


def test_bar_renders_proportionally_filled_blocks_and_one_decimal_pct():
    out = monitor.bar(50.0, width=10)
    assert out == "[green]█████░░░░░[/green] 50.0%"


def test_bar_rounds_down_partial_blocks():
    out = monitor.bar(42.5, width=10)
    assert out.startswith("[green]") and "█" * 4 + "░" * 6 in out
    assert out.endswith("42.5%")


def test_bar_uses_green_below_sixty_percent():
    assert "[green]" in monitor.bar(59.9)


def test_bar_uses_yellow_from_sixty_to_under_eighty_five():
    assert "[yellow]" in monitor.bar(60.0)
    assert "[yellow]" in monitor.bar(84.9)


def test_bar_uses_red_at_eighty_five_percent_and_above():
    assert "[red]" in monitor.bar(85.0)
    assert "[red]" in monitor.bar(100.0)


def test_bar_at_zero_is_all_empty_blocks():
    out = monitor.bar(0, width=8)
    assert "░" * 8 in out
    assert "█" not in out
    assert out.endswith(" 0.0%")


def test_bar_at_hundred_percent_is_all_full_blocks():
    out = monitor.bar(100.0, width=8)
    assert "█" * 8 in out
    assert "░" not in out


def bar_body(rendered: str) -> str:
    """Extract just the block characters out of a rendered bar."""
    return re.match(r"\[(\w+)\](.*?)\[/?\w+\]", rendered).group(2)


def table_rows(table) -> list[list[str]]:
    """Cells live on the columns in rich 15, so rebuild row-major cell lists."""
    n_rows = len(table.rows)
    return [
        [str(table.columns[i]._cells[r]) for i in range(len(table.columns))] for r in range(n_rows)
    ]


def table_headers(table) -> list[str]:
    return [str(c.header) for c in table.columns]


def test_bar_always_emits_exactly_width_blocks_for_in_range_pct():
    for pct in (0.0, 1.0, 33.3, 66.6, 99.9):
        assert len(bar_body(monitor.bar(pct, width=20))) == 20


def test_bar_defaults_to_width_twenty():
    body = bar_body(monitor.bar(35.0))
    assert len(body) == 20
    assert body.count("█") == 7


def test_build_display_renders_cpu_memory_load_and_uptime():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    console, buf = make_console()
    console.print(monitor.build_display("10.0.4.21", stats))
    out = buf.getvalue()

    assert "porthole monitor" in out and "10.0.4.21" in out
    assert "CPU" in out
    assert "12.5%" in out
    assert "8192M / 16384M" in out
    assert "50.0%" in out
    assert "0.52 0.41 0.38" in out
    assert "up 12 days, 4 hours" in out


@pytest.mark.xfail(
    reason="build_display embeds str(proc_table) in a Panel string, so the process "
    "table renders as '<rich.table.Table object at 0x...>' and never reaches the terminal",
    strict=True,
)
def test_build_display_renders_top_process_rows():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    stats["procs"] = [["root", "1.2", "0.5", "/sbin/init"], ["broken", "9.9"]]
    console, buf = make_console()
    console.print(monitor.build_display("10.0.4.21", stats))
    out = buf.getvalue()

    assert "Top Processes" in out
    assert "www-data" in out or "root" in out
    assert "/sbin/init" in out
    assert "broken" not in out


def test_build_display_omits_the_process_table_repr_from_output():
    """Locks in the current (buggy) shape: the table is stringified, not rendered."""
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    console, buf = make_console()
    console.print(monitor.build_display("10.0.4.21", stats))
    out = buf.getvalue()

    assert "Top Processes" not in out
    assert "rich.table.Table object" in out
    assert "www-data" not in out


@pytest.mark.xfail(
    reason="build_display has `Columns([...]) if False else ...` — the disk and network "
    "panels are constructed and then discarded",
    strict=True,
)
def test_build_display_shows_disk_and_network_panel_data():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    console, buf = make_console()
    console.print(monitor.build_display("10.0.4.21", stats))
    out = buf.getvalue()

    assert "45G / 98G" in out
    assert "44G" in out
    assert "50%" in out
    assert "Connections" in out
    assert "Users" in out


def test_build_display_handles_zero_memory_total_without_dividing_by_zero():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    stats["mem_total"] = 0
    stats["mem_used"] = 0
    console, buf = make_console()
    console.print(monitor.build_display("10.0.4.21", stats))
    out = buf.getvalue()

    assert "0M / 0M" in out
    assert "0.0%" in out


def test_build_display_returns_a_panel_titled_with_the_host():
    stats = monitor.get_system_stats(FakeSSH(STATS_RESPONSES))
    panel = monitor.build_display("10.0.4.21", stats)
    assert isinstance(panel, Panel)
    assert "porthole monitor — 10.0.4.21" in panel.title


class FakeLive:
    def __init__(self, *args, **kwargs):
        self.updates = []
        self.started = False
        self.stopped = False
        self.kwargs = kwargs

    def __enter__(self):
        self.started = True
        return self

    def __exit__(self, *_):
        self.stopped = True
        return False

    def update(self, renderable):
        self.updates.append(renderable)


def run_monitor_with(monkeypatch, responses=None, sleep_plan=None, interval=3):
    """Drive run_monitor to completion; sleep_plan is a list of (sleep or raise)."""
    client_cls, created = make_client(responses if responses is not None else STATS_RESPONSES)
    lives = []

    def live_factory(*args, **kwargs):
        live = FakeLive(*args, **kwargs)
        lives.append(live)
        return live

    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        plan = sleep_plan or [None]
        action = plan[len(sleeps) - 1] if len(sleeps) <= len(plan) else KeyboardInterrupt
        if isinstance(action, type) and issubclass(action, BaseException):
            raise action()
        if isinstance(action, BaseException):
            raise action

    monkeypatch.setattr(monitor, "SSHClient", client_cls)
    monkeypatch.setattr(monitor, "Live", live_factory)
    monkeypatch.setattr(monitor.time, "sleep", fake_sleep)
    console, buf = make_console()
    monkeypatch.setattr(monitor, "console", console)

    monitor.run_monitor("10.0.4.21", "root", "hunter2", interval=interval)
    return created, lives, sleeps, buf.getvalue()


def test_run_monitor_connects_with_supplied_credentials(monkeypatch):
    created, _, _, _ = run_monitor_with(monkeypatch)
    assert len(created) == 1
    assert created[0].host == "10.0.4.21"
    assert created[0].username == "root"
    assert created[0].password == "hunter2"
    assert created[0].connected is True
    assert created[0].disconnected is True


def test_run_monitor_prints_connecting_and_connected_banners(monkeypatch):
    _, _, _, out = run_monitor_with(monkeypatch)
    assert "Connecting to 10.0.4.21" in out
    assert "Connected" in out


def test_run_monitor_sleeps_for_the_requested_interval_between_refreshes(monkeypatch):
    _, _, sleeps, _ = run_monitor_with(
        monkeypatch, sleep_plan=[None, KeyboardInterrupt], interval=7
    )
    assert sleeps == [7, 7]


def test_run_monitor_updates_live_once_per_iteration_before_sleeping(monkeypatch):
    _, lives, _, _ = run_monitor_with(monkeypatch, sleep_plan=[KeyboardInterrupt])
    assert len(lives) == 1
    assert lives[0].started is True
    assert lives[0].stopped is True
    assert len(lives[0].updates) == 1


def test_run_monitor_renders_metric_table_with_cpu_memory_and_disk_rows(monkeypatch):
    _, lives, _, _ = run_monitor_with(monkeypatch, sleep_plan=[KeyboardInterrupt])
    group = lives[0].updates[0]
    assert isinstance(group, Group)
    metric_table, proc_table = group.renderables
    rows = {r[0]: r[1] for r in table_rows(metric_table)}

    assert set(rows) == {"CPU", "Memory", "Disk", "Load", "Uptime", "Net conns", "Users"}
    assert table_headers(metric_table) == ["Metric", "Value"]
    assert rows["CPU"] == "[green]██░░░░░░░░░░░░░░░░░░[/green] 12.5%"
    assert "8192M / 16384M" in rows["Memory"]
    assert "50.0%" in rows["Memory"]
    assert rows["Disk"] == "45G / 98G (50%)"
    assert rows["Load"] == "0.52 0.41 0.38"
    assert rows["Uptime"] == "up 12 days, 4 hours"
    assert rows["Net conns"] == "7"
    assert rows["Users"] == "2"


def test_run_monitor_renders_process_table_with_four_column_rows(monkeypatch):
    _, lives, _, _ = run_monitor_with(monkeypatch, sleep_plan=[KeyboardInterrupt])
    _, proc_table = lives[0].updates[0].renderables
    rows = table_rows(proc_table)

    assert len(rows) == 3
    assert rows[1] == ["www-data", "3.4", "2.1", "nginx"]
    assert table_headers(proc_table) == ["User", "CPU%", "MEM%", "Command"]


def test_run_monitor_skips_process_rows_with_fewer_than_four_fields(monkeypatch):
    responses = dict(
        STATS_RESPONSES, **{"ps aux": "root 1.2 0.5 init\nshort 9.9\nnginx 0.1 0.1 nginx"}
    )
    _, lives, _, _ = run_monitor_with(
        monkeypatch, responses=responses, sleep_plan=[KeyboardInterrupt]
    )
    _, proc_table = lives[0].updates[0].renderables
    rows = table_rows(proc_table)

    assert rows == [["root", "1.2", "0.5", "init"], ["nginx", "0.1", "0.1", "nginx"]]


def test_run_monitor_refreshes_again_after_each_sleep(monkeypatch):
    created, lives, sleeps, _ = run_monitor_with(monkeypatch, sleep_plan=[None, KeyboardInterrupt])
    assert len(lives[0].updates) == 2
    assert len(sleeps) == 2
    first, second = [g.renderables[0] for g in lives[0].updates]
    assert table_rows(first) == table_rows(second)
    assert len(created[0].commands) == 2 * 8


def test_run_monitor_re_queries_stats_every_iteration(monkeypatch):
    created, lives, _, _ = run_monitor_with(monkeypatch, sleep_plan=[None, KeyboardInterrupt])
    first_rows = {r[0]: r[1] for r in table_rows(lives[0].updates[0].renderables[0])}
    assert "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'" in created[0].commands
    assert created[0].commands.count("nproc") == 0
    assert created[0].commands.count("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'") == 2
    assert first_rows["CPU"].endswith("12.5%")


def test_run_monitor_exits_immediately_when_first_sleep_is_interrupted(monkeypatch):
    _, lives, sleeps, _ = run_monitor_with(monkeypatch, sleep_plan=[KeyboardInterrupt])
    assert len(lives[0].updates) == 1
    assert sleeps == [3]


def test_run_monitor_survives_zero_memory_total_when_rendering(monkeypatch):
    responses = dict(STATS_RESPONSES, **{"free -m": "0 0 0"})
    _, lives, _, _ = run_monitor_with(
        monkeypatch, responses=responses, sleep_plan=[KeyboardInterrupt]
    )
    rows = {r[0]: r[1] for r in table_rows(lives[0].updates[0].renderables[0])}
    assert rows["Memory"] == "[green]░░░░░░░░░░░░░░░░░░░░[/green] 0.0% (0M / 0M)"
