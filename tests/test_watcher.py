"""Unit tests for porthole.watcher — log tailing driven by a fake SSH channel.

The follow loops are infinite by design, so they are never run against a real
host: a scripted fake channel supplies chunks and then reports exit-status-ready
so the loop terminates deterministically, and `watcher.time` is replaced with a
recording stub so the poll delay never actually sleeps.
"""

import io

import pytest
from rich.console import Console

from porthole import watcher


class FakeTime:
    """Records sleep() calls instead of blocking."""

    def __init__(self):
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class FakeChannel:
    """Scripted stand-in for a paramiko Channel.

    `actions` is a list of tuples consumed by the watcher loop:
      ("data", b"...") -> recv_ready() is True and recv() returns the payload
      ("eof",)        -> nothing readable and exit_status_ready() is True
      ("interrupt",)  -> recv() raises KeyboardInterrupt
    `idle_polls` pre-programs N leading iterations where neither recv_ready()
    nor exit_status_ready() is True, so the loop takes its sleep branch.
    """

    def __init__(self, actions, idle_polls=0):
        self.actions = list(actions)
        self.idle_polls = idle_polls
        self.commands = []
        self.recv_sizes = []
        self.pty_requested = False
        self.closed = False

    def get_pty(self):
        self.pty_requested = True

    def exec_command(self, cmd):
        self.commands.append(cmd)

    def recv_ready(self):
        if self.idle_polls > 0:
            self.idle_polls -= 1
            return False
        return bool(self.actions) and self.actions[0][0] in ("data", "interrupt")

    def exit_status_ready(self):
        if self.idle_polls > 0:
            return False
        return (not self.actions) or self.actions[0][0] == "eof"

    def recv(self, size):
        action = self.actions.pop(0)
        kind = action[0]
        payload = action[1] if len(action) > 1 else b""
        self.recv_sizes.append(size)
        if kind == "interrupt":
            raise KeyboardInterrupt
        return payload

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, channel):
        self.channel = channel
        self.sessions_opened = 0

    def open_session(self):
        self.sessions_opened += 1
        return self.channel


def make_ssh_class(channel):
    """Build a FakeSSHClient class bound to `channel` and its instance list."""

    class FakeSSHClient:
        instances = []

        def __init__(self, host, username, password=None, key_path=None, port=22, timeout=10):
            self.host = host
            self.username = username
            self.password = password
            self.transport = FakeTransport(channel)
            self._client = self
            self.connect_calls = 0
            self.disconnect_calls = 0
            FakeSSHClient.instances.append(self)

        def get_transport(self):
            return self.transport

        def connect(self, retries=3, retry_delay=2.0):
            self.connect_calls += 1
            return self

        def disconnect(self):
            self.disconnect_calls += 1

        def __enter__(self):
            return self.connect()

        def __exit__(self, *_):
            self.disconnect()

    return FakeSSHClient


@pytest.fixture
def rec_console(monkeypatch):
    console = Console(
        record=True, file=io.StringIO(), width=200, no_color=True, force_terminal=False
    )
    monkeypatch.setattr(watcher, "console", console)
    return console


@pytest.fixture
def fake_time(monkeypatch):
    stub = FakeTime()
    monkeypatch.setattr(watcher, "time", stub)
    return stub


@pytest.fixture
def install_ssh(monkeypatch):
    def _install(actions):
        # ("idle",) markers only drive the idle_polls counter — strip them so
        # they are never left as an unconsumed action that would hang the loop.
        idle_count = sum(1 for a in actions if a and a[0] == "idle")
        real_actions = [a for a in actions if not a or a[0] != "idle"]
        channel = FakeChannel(real_actions, idle_polls=idle_count)
        cls = make_ssh_class(channel)
        monkeypatch.setattr(watcher, "SSHClient", cls)
        return channel, cls

    return _install


# --------------------------------------------------------------------------
# colorize_line
# --------------------------------------------------------------------------


def test_colorize_line_stylizes_whole_line_bold_red_when_it_contains_error():
    text = watcher.colorize_line("ERROR: disk gone")
    assert text.plain == "ERROR: disk gone"
    assert [(s.start, s.end, s.style) for s in text.spans] == [(0, 16, "bold red")]


def test_colorize_line_matches_patterns_case_insensitively():
    text = watcher.colorize_line("fatal Error raised")
    assert [(s.start, s.end, s.style) for s in text.spans] == [(0, 18, "bold red")]


def test_colorize_line_leaves_line_without_known_pattern_unstyled():
    text = watcher.colorize_line("started listening on port 8080")
    assert text.plain == "started listening on port 8080"
    assert text.spans == []


def test_colorize_line_applies_only_the_first_matching_pattern_in_dict_order():
    # "fail" is declared before "critical", so a line containing both must not
    # pick up the "bold red reverse" critical style.
    text = watcher.colorize_line("FAIL in a critical service")
    assert [s.style for s in text.spans] == ["bold red"]


def test_colorize_line_uses_critical_reverse_style_when_critical_is_first_match():
    text = watcher.colorize_line("CRITICAL: database offline")
    assert [s.style for s in text.spans] == ["bold red reverse"]


def test_colorize_line_uses_bold_yellow_for_warn_before_warning():
    text = watcher.colorize_line("Warning: low memory")
    assert [s.style for s in text.spans] == ["bold yellow"]


def test_colorize_line_uses_bold_green_for_ok():
    text = watcher.colorize_line("deployment ok")
    assert [s.style for s in text.spans] == ["bold green"]


def test_colorize_line_uses_cyan_for_info():
    text = watcher.colorize_line("INFO request served")
    assert [s.style for s in text.spans] == ["cyan"]


def test_colorize_line_uses_plain_red_for_traceback():
    text = watcher.colorize_line("Traceback (most recent call last)")
    assert [s.style for s in text.spans] == ["red"]


def test_highlight_patterns_map_every_level_to_a_style():
    patterns = watcher.HIGHLIGHT_PATTERNS
    assert patterns["error"] == patterns["fail"] == patterns["exception"] == "bold red"
    assert patterns["warn"] == patterns["warning"] == "bold yellow"
    assert patterns["success"] == patterns["ok"] == "bold green"
    assert patterns["info"] == "cyan"
    assert patterns["critical"] == "bold red reverse"
    assert patterns["traceback"] == "red"


# --------------------------------------------------------------------------
# watch_file
# --------------------------------------------------------------------------


def test_watch_file_executes_tail_follow_command_with_requested_line_count(
    install_ssh, rec_console, fake_time
):
    channel, _ = install_ssh([])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog", lines=25)
    assert channel.commands == ["tail -n 25 -f /var/log/syslog"]


def test_watch_file_defaults_to_tailing_fifty_lines(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/app.log")
    assert channel.commands == ["tail -n 50 -f /var/log/app.log"]


def test_watch_file_requests_a_pty_before_executing(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert channel.pty_requested is True


def test_watch_file_prints_every_complete_line_from_the_stream(install_ssh, rec_console, fake_time):
    install_ssh([("data", b"first line\nsecond line\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    out = rec_console.export_text()
    assert "first line" in out
    assert "second line" in out


def test_watch_file_reassembles_a_line_split_across_two_chunks(install_ssh, rec_console, fake_time):
    install_ssh([("data", b"ERRO"), ("data", b"R: split\nok\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    out = rec_console.export_text()
    assert "ERROR: split" in out
    assert "ok" in out


def test_watch_file_does_not_print_a_trailing_line_without_a_newline(
    install_ssh, rec_console, fake_time
):
    install_ssh([("data", b"complete\npartial-without-newline")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    out = rec_console.export_text()
    assert "complete" in out
    assert "partial-without-newline" not in out


def test_watch_file_reads_in_4096_byte_chunks(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([("data", b"x\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert channel.recv_sizes == [4096]


def test_watch_file_polls_with_sleep_when_nothing_is_ready_yet(install_ssh, rec_console, fake_time):
    install_ssh([("idle",), ("data", b"late line\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert fake_time.sleeps == [0.05]
    assert "late line" in rec_console.export_text()


def test_watch_file_breaks_the_loop_when_exit_status_is_ready(install_ssh, rec_console, fake_time):
    install_ssh([("data", b"a\n"), ("eof",), ("data", b"never\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    out = rec_console.export_text()
    assert "a" in out
    assert "never" not in out


def test_watch_file_closes_the_channel_after_the_stream_ends(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([("data", b"a\n")])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert channel.closed is True


def test_watch_file_disconnects_the_ssh_client_after_the_stream_ends(
    install_ssh, rec_console, fake_time
):
    channel, cls = install_ssh([])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert len(cls.instances) == 1
    client = cls.instances[0]
    assert client.connect_calls == 1
    assert client.disconnect_calls == 1
    assert (client.host, client.username, client.password) == ("10.0.0.1", "deploy", "pw")


def test_watch_file_prints_stopped_and_still_closes_on_keyboard_interrupt(
    install_ssh, rec_console, fake_time
):
    channel, cls = install_ssh([("interrupt",)])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/syslog")
    assert "Stopped." in rec_console.export_text()
    assert channel.closed is True
    assert cls.instances[0].disconnect_calls == 1


def test_watch_file_banner_names_the_watched_path_and_host(install_ssh, rec_console, fake_time):
    install_ssh([])
    watcher.watch_file("10.0.0.1", "deploy", "pw", "/var/log/nginx/error.log")
    out = rec_console.export_text()
    assert "/var/log/nginx/error.log" in out
    assert "10.0.0.1" in out
    assert "Ctrl+C to stop" in out


# --------------------------------------------------------------------------
# watch_logs
# --------------------------------------------------------------------------


def test_watch_logs_executes_journalctl_follow_without_pager(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    assert channel.commands == ["journalctl -f --no-pager"]


def test_watch_logs_appends_unit_filter_when_service_given(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([])
    watcher.watch_logs("10.0.0.1", "deploy", "pw", service="nginx")
    assert channel.commands == ["journalctl -f --no-pager -u nginx"]


def test_watch_logs_omits_unit_filter_when_service_is_none(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([])
    watcher.watch_logs("10.0.0.1", "deploy", "pw", service=None)
    assert channel.commands == ["journalctl -f --no-pager"]
    assert "-u" not in channel.commands[0]


def test_watch_logs_banner_includes_the_service_name(install_ssh, rec_console, fake_time):
    install_ssh([])
    watcher.watch_logs("10.0.0.1", "deploy", "pw", service="sshd")
    out = rec_console.export_text()
    assert "journalctl -u sshd" in out


def test_watch_logs_banner_shows_bare_journalctl_without_service(
    install_ssh, rec_console, fake_time
):
    install_ssh([])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    out = rec_console.export_text()
    assert "Watching journalctl on 10.0.0.1" in out


def test_watch_logs_prints_each_journal_line(install_ssh, rec_console, fake_time):
    install_ssh([("data", b"Jan 01 host nginx: started\nJan 01 host nginx: stopped\n")])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    out = rec_console.export_text()
    assert "nginx: started" in out
    assert "nginx: stopped" in out


def test_watch_logs_sleeps_while_journal_is_quiet(install_ssh, rec_console, fake_time):
    install_ssh([("idle",), ("idle",), ("data", b"quiet then loud\n")])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    assert fake_time.sleeps == [0.05, 0.05]
    assert "quiet then loud" in rec_console.export_text()


def test_watch_logs_requests_pty_and_closes_channel(install_ssh, rec_console, fake_time):
    channel, _ = install_ssh([("data", b"line\n")])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    assert channel.pty_requested is True
    assert channel.closed is True


def test_watch_logs_handles_keyboard_interrupt_and_disconnects(install_ssh, rec_console, fake_time):
    channel, cls = install_ssh([("interrupt",)])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    assert "Stopped." in rec_console.export_text()
    assert channel.closed is True
    assert cls.instances[0].disconnect_calls == 1


def test_watch_logs_drops_partial_trailing_line(install_ssh, rec_console, fake_time):
    install_ssh([("data", b"full line\nhalf")])
    watcher.watch_logs("10.0.0.1", "deploy", "pw")
    out = rec_console.export_text()
    assert "full line" in out
    assert "half" not in out
