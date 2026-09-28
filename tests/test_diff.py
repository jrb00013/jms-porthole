"""Unit tests for porthole.diff — local files live in tmp_path, SSH is always faked."""

import pytest

from porthole import diff, store


class FakeSSH:
    """Serves canned `cat <path>` output and records what was requested."""

    instances = []
    contents = {}
    connect_error = None

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
        path = cmd[len("cat ") :]
        return type(self).contents.get(path, "")


class RecordingConsole:
    def __init__(self):
        self.printed = []

    def print(self, *args, **kwargs):
        self.printed.append(args[0] if args else None)

    def clear(self):
        pass

    def syntax_texts(self):
        return [p.code for p in self.printed if hasattr(p, "code")]


@pytest.fixture
def fake_ssh(monkeypatch):
    FakeSSH.instances = []
    FakeSSH.contents = {}
    FakeSSH.connect_error = None
    monkeypatch.setattr("porthole.ssh.SSHClient", FakeSSH)
    console = RecordingConsole()
    monkeypatch.setattr(diff, "console", console)
    return FakeSSH


@pytest.fixture
def local_file(tmp_path):
    def _write(name, text):
        path = tmp_path / name
        path.write_text(text)
        return path

    return _write


# --------------------------------------------------------------------------
# diff_local_remote()
# --------------------------------------------------------------------------


def test_diff_local_remote_fetches_the_remote_file_with_cat(fake_ssh, local_file):
    local = local_file("a.conf", "x\n")
    fake_ssh.contents = {"/etc/a.conf": "y\n"}
    diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf")
    assert fake_ssh.instances[0].commands == ["cat /etc/a.conf"]


def test_diff_local_remote_reports_removed_and_added_lines(fake_ssh, local_file):
    local = local_file("a.conf", "keep\nold\n")
    fake_ssh.contents = {"/etc/a.conf": "keep\nnew\n"}
    console = RecordingConsole()
    diff.console = console

    diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf")

    text = console.syntax_texts()[0]
    assert "-old" in text
    assert "+new" in text
    assert " keep" in text


def test_diff_local_remote_labels_the_two_sides_local_and_host(fake_ssh, local_file):
    local = local_file("a.conf", "one\n")
    fake_ssh.contents = {"/etc/a.conf": "two\n"}
    console = RecordingConsole()
    diff.console = console

    diff.diff_local_remote("10.0.0.1", "u", "p", str(local), "/etc/a.conf")

    text = console.syntax_texts()[0]
    assert f"local:{local}" in text
    assert "10.0.0.1:/etc/a.conf" in text


def test_diff_local_remote_prints_identical_when_contents_match(fake_ssh, local_file):
    local = local_file("a.conf", "same\nlines\n")
    fake_ssh.contents = {"/etc/a.conf": "same\nlines\n"}
    console = RecordingConsole()
    diff.console = console

    assert diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf") is None

    assert console.syntax_texts() == []
    assert console.printed == ["[green]Files are identical.[/green]"]


def test_diff_local_remote_expands_a_tilde_in_the_local_path(
    fake_ssh, local_file, monkeypatch, tmp_path
):
    home = tmp_path / "home"
    home.mkdir()
    (home / "rc").write_text("home-line\n")
    monkeypatch.setenv("HOME", str(home))
    fake_ssh.contents = {"/etc/rc": "remote-line\n"}
    console = RecordingConsole()
    diff.console = console

    diff.diff_local_remote("h", "u", "p", "~/rc", "/etc/rc")

    assert str(home / "rc") in console.syntax_texts()[0]


def test_diff_local_remote_raises_file_not_found_for_a_missing_local_file(fake_ssh, tmp_path):
    fake_ssh.contents = {"/etc/a.conf": "x\n"}
    with pytest.raises(FileNotFoundError):
        diff.diff_local_remote("h", "u", "p", str(tmp_path / "nope.conf"), "/etc/a.conf")
    assert fake_ssh.instances == []


def test_diff_local_remote_propagates_an_ssh_failure(fake_ssh, local_file):
    local = local_file("a.conf", "x\n")
    fake_ssh.connect_error = RuntimeError("auth failed")
    with pytest.raises(RuntimeError, match="auth failed"):
        diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf")


def test_diff_local_remote_closes_the_ssh_session(fake_ssh, local_file):
    local = local_file("a.conf", "x\n")
    fake_ssh.contents = {"/etc/a.conf": "y\n"}
    diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf")
    assert fake_ssh.instances[0].disconnected is True


def test_diff_local_remote_normalises_a_remote_file_with_no_trailing_newline(fake_ssh, local_file):
    local = local_file("a.conf", "line\n")
    fake_ssh.contents = {"/etc/a.conf": "line"}  # remote `cat` output has no trailing \n
    console = RecordingConsole()
    diff.console = console

    diff.diff_local_remote("h", "u", "p", str(local), "/etc/a.conf")

    assert console.printed == ["[green]Files are identical.[/green]"]


# --------------------------------------------------------------------------
# diff_remote_remote()
# --------------------------------------------------------------------------


def test_diff_remote_remote_reads_both_paths_with_cat(fake_ssh):
    diff.diff_remote_remote("h", "u", "p", "/etc/a", "/etc/b")
    assert fake_ssh.instances[0].commands == ["cat /etc/a", "cat /etc/b"]


def test_diff_remote_remote_reports_removed_and_added_lines(fake_ssh):
    fake_ssh.contents = {"/etc/a": "keep\nold\n", "/etc/b": "keep\nnew\n"}
    console = RecordingConsole()
    diff.console = console

    diff.diff_remote_remote("h", "u", "p", "/etc/a", "/etc/b")

    text = console.syntax_texts()[0]
    assert "-old" in text
    assert "+new" in text


def test_diff_remote_remote_labels_fromfile_and_tofile(fake_ssh):
    fake_ssh.contents = {"/etc/a": "one\n", "/etc/b": "two\n"}
    console = RecordingConsole()
    diff.console = console

    diff.diff_remote_remote("h", "u", "p", "/etc/a", "/etc/b")

    text = console.syntax_texts()[0]
    assert "--- /etc/a" in text
    assert "+++ /etc/b" in text


def test_diff_remote_remote_prints_identical_for_matching_files(fake_ssh):
    fake_ssh.contents = {"/etc/a": "same\n", "/etc/b": "same\n"}
    console = RecordingConsole()
    diff.console = console

    assert diff.diff_remote_remote("h", "u", "p", "/etc/a", "/etc/b") is None

    assert console.syntax_texts() == []
    assert console.printed == ["[green]Files are identical.[/green]"]


def test_diff_remote_remote_treats_two_empty_files_as_identical(fake_ssh):
    fake_ssh.contents = {}
    console = RecordingConsole()
    diff.console = console
    diff.diff_remote_remote("h", "u", "p", "/etc/empty-a", "/etc/empty-b")
    assert console.printed == ["[green]Files are identical.[/green]"]


def test_diff_remote_remote_propagates_an_ssh_failure(fake_ssh):
    fake_ssh.connect_error = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        diff.diff_remote_remote("h", "u", "p", "/etc/a", "/etc/b")


# --------------------------------------------------------------------------
# diff_against_history() — redirected away from ~/.porthole by patching store.diff_since_last
# --------------------------------------------------------------------------


@pytest.fixture
def history_env(monkeypatch):
    calls = []
    console = RecordingConsole()
    monkeypatch.setattr(diff, "console", console)
    return calls, console


def test_diff_against_history_announces_the_baseline_when_nothing_was_stored(
    monkeypatch, history_env
):
    calls, console = history_env

    def fake(kind, target, data):
        calls.append((kind, target, data))
        return {"has_previous": False, "added": data, "removed": [], "changed": False}

    monkeypatch.setattr(store, "diff_since_last", fake)
    diff.diff_against_history("netmap", "10.0.0.0/24", [{"host": "a"}])

    assert calls == [("netmap", "10.0.0.0/24", [{"host": "a"}])]
    assert "No previous 'netmap' run recorded for 10.0.0.0/24" in console.printed[0]


def test_diff_against_history_reports_no_change_when_results_match(monkeypatch, history_env):
    _, console = history_env
    monkeypatch.setattr(
        store,
        "diff_since_last",
        lambda k, t, d: {
            "has_previous": True,
            "changed": False,
            "added": [],
            "removed": [],
            "previous_ts": "2026-01-01T00:00:00+00:00",
        },
    )
    diff.diff_against_history("scan", "h", {"22": "ssh"})
    assert console.printed == [
        "[green]No change since last 'scan' run for h (2026-01-01T00:00:00+00:00).[/green]"
    ]


def test_diff_against_history_prints_added_and_removed_items(monkeypatch, history_env):
    _, console = history_env
    monkeypatch.setattr(
        store,
        "diff_since_last",
        lambda k, t, d: {
            "has_previous": True,
            "changed": True,
            "added": [{"host": "c"}],
            "removed": [{"host": "a"}],
            "previous_ts": "TS",
        },
    )
    diff.diff_against_history("netmap", "cidr", [])

    joined = "\n".join(console.printed)
    assert "Changes since last 'netmap' run for cidr (TS)" in joined
    assert "[green]+ {'host': 'c'}[/green]" in joined
    assert "[red]- {'host': 'a'}[/red]" in joined


def test_diff_against_history_tolerates_null_added_and_removed_lists(monkeypatch, history_env):
    _, console = history_env
    monkeypatch.setattr(
        store,
        "diff_since_last",
        lambda k, t, d: {
            "has_previous": True,
            "changed": True,
            "added": None,
            "removed": None,
            "previous_ts": "TS",
        },
    )
    diff.diff_against_history("vuln", "h", {"a": 1})
    assert len(console.printed) == 1  # header only, no +/- lines


def test_diff_against_history_delegates_to_the_store_and_writes_nothing_it_owns(
    monkeypatch, tmp_path, history_env
):
    calls, _ = history_env

    def fake(kind, target, data):
        calls.append((kind, target, data))
        return {"has_previous": False, "added": data, "removed": [], "changed": False}

    monkeypatch.setattr(store, "diff_since_last", fake)
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "history.db")
    diff.diff_against_history("scan", "h", {"a": 1})
    assert calls == [("scan", "h", {"a": 1})]
    assert not (tmp_path / "history.db").exists()
