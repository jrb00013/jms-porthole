"""Unit tests for porthole.ssh — paramiko.SSHClient is always faked, no real sockets."""

import socket

import paramiko
import pytest

from porthole import ssh


class FakeChannel:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code

    def recv_exit_status(self):
        return self.exit_code


class FakeStream:
    def __init__(self, data, channel):
        self._data = data.encode() if isinstance(data, str) else data
        self.channel = channel

    def read(self):
        return self._data


class FakeSFTP:
    def __init__(self):
        self.put_calls = []
        self.get_calls = []
        self.closed = False

    def put(self, local_path, remote_path):
        self.put_calls.append((local_path, remote_path))

    def get(self, remote_path, local_path):
        self.get_calls.append((remote_path, local_path))

    def close(self):
        self.closed = True


class FakeParamikoClient:
    """Stand-in for paramiko.SSHClient that records everything the source does to it."""

    def __init__(self):
        self.policy = None
        self.connect_calls = []
        self.connect_errors = []  # raised one per call, in order
        self.exec_calls = []
        self.exec_results = []  # (stdout, stderr, exit_code) tuples
        self.exec_error = None
        self.sftp = FakeSFTP()
        self.sftp_handle = None
        self.closed = False

    # -- paramiko API -----------------------------------------------------
    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connect_calls.append(kwargs)
        if self.connect_errors:
            raise self.connect_errors.pop(0)

    def exec_command(self, cmd, timeout=None):
        self.exec_calls.append((cmd, timeout))
        if self.exec_error is not None:
            raise self.exec_error
        out, err, code = self.exec_results[0] if self.exec_results else ("", "", 0)
        channel = FakeChannel(code)
        return (None, FakeStream(out, channel), FakeStream(err, channel))

    def open_sftp(self):
        if self.sftp_handle is None:
            self.sftp_handle = self.sftp
        return self.sftp_handle

    def close(self):
        self.closed = True


class AlwaysFailsClient(FakeParamikoClient):
    """A paramiko stand-in whose connect() always raises, counting attempts."""

    error = OSError("no route to host")

    def __init__(self):
        super().__init__()
        self.attempts = 0

    def connect(self, **kwargs):
        self.attempts += 1
        raise type(self).error


@pytest.fixture
def paramiko_clients(monkeypatch):
    """Patch paramiko.SSHClient in the module under test; return the created fakes."""
    created = []

    def factory():
        client = FakeParamikoClient()
        created.append(client)
        return client

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    return created


def connected(paramiko_clients, host="h1", username="u", password="p", key_path=None, port=22):
    client = ssh.SSHClient(host, username, password, key_path=key_path, port=port)
    client.connect()
    return client, paramiko_clients[-1]


# --------------------------------------------------------------------------
# connect(): policy, kwargs, retry loop
# --------------------------------------------------------------------------


def test_connect_sets_auto_add_missing_host_key_policy(paramiko_clients):
    connected(paramiko_clients)
    assert isinstance(paramiko_clients[0].policy, paramiko.AutoAddPolicy)


def test_connect_passes_hostname_port_username_and_timeout_to_paramiko(paramiko_clients):
    _, fake = connected(paramiko_clients, host="10.0.0.9", username="deploy", port=2222)
    fake.connect_calls[0]["hostname"] = "10.0.0.9"
    kwargs = fake.connect_calls[0]
    assert kwargs["hostname"] == "10.0.0.9"
    assert kwargs["port"] == 2222
    assert kwargs["username"] == "deploy"
    assert kwargs["timeout"] == 10


def test_connect_uses_custom_timeout_value(paramiko_clients):
    c = ssh.SSHClient("h", "u", "p", timeout=42)
    c.connect()
    assert paramiko_clients[0].connect_calls[0]["timeout"] == 42


def test_connect_passes_key_filename_when_key_path_given(paramiko_clients):
    _, fake = connected(paramiko_clients, password=None, key_path="/tmp/id_ed25519")
    kwargs = fake.connect_calls[0]
    assert kwargs["key_filename"] == "/tmp/id_ed25519"
    assert "password" not in kwargs


def test_connect_passes_password_when_no_key_path_given(paramiko_clients):
    _, fake = connected(paramiko_clients, password="s3cret")
    kwargs = fake.connect_calls[0]
    assert kwargs["password"] == "s3cret"
    assert "key_filename" not in kwargs


def test_connect_key_path_takes_precedence_over_password(paramiko_clients):
    _, fake = connected(paramiko_clients, password="s3cret", key_path="/tmp/id_rsa")
    kwargs = fake.connect_calls[0]
    assert kwargs["key_filename"] == "/tmp/id_rsa"
    assert "password" not in kwargs


def test_connect_passes_neither_credential_when_both_absent(paramiko_clients):
    _, fake = connected(paramiko_clients, password=None, key_path=None)
    kwargs = fake.connect_calls[0]
    assert "key_filename" not in kwargs
    assert "password" not in kwargs


def test_connect_returns_self_for_fluent_chaining(paramiko_clients):
    client = ssh.SSHClient("h", "u", "p")
    assert client.connect() is client


def test_connect_reuses_the_same_paramiko_client_across_retries(paramiko_clients):
    c = ssh.SSHClient("h", "u", "p")
    c.connect(retries=3)
    assert len(paramiko_clients) == 1


def test_connect_retries_then_succeeds_after_n_failures(monkeypatch):
    sleeps = []
    monkeypatch.setattr(ssh.time, "sleep", lambda d: sleeps.append(d))

    calls = {"n": 0}
    created = []

    def flaky_connect(self, **kwargs):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise paramiko.AuthenticationException("nope")

    def factory():
        fake = FakeParamikoClient()
        created.append(fake)
        return fake

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    monkeypatch.setattr(FakeParamikoClient, "connect", flaky_connect)

    client = ssh.SSHClient("h", "u", "p")
    assert client.connect(retries=3, retry_delay=0.5) is client
    assert calls["n"] == 3
    assert len(created) == 1  # one paramiko client reused across retries
    # flaky_connect replaces FakeParamikoClient.connect, so connect_calls is unused;
    # the attempt counter is the authoritative signal that retries ran.
    assert sleeps == [0.5, 0.5]


def test_connect_raises_connection_error_after_exhausting_retries(paramiko_clients, monkeypatch):
    sleeps = []
    monkeypatch.setattr(ssh.time, "sleep", lambda d: sleeps.append(d))

    made = []

    def factory():
        fake = AlwaysFailsClient()
        made.append(fake)
        return fake

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)

    client = ssh.SSHClient("10.0.0.1", "u", "p", port=2222)
    with pytest.raises(ConnectionError) as excinfo:
        client.connect(retries=4, retry_delay=1.25)

    message = str(excinfo.value)
    assert "10.0.0.1:2222" in message
    assert "no route to host" in message
    assert sleeps == [1.25, 1.25, 1.25]


def test_connect_attempts_exactly_the_requested_number_of_times(paramiko_clients, monkeypatch):
    monkeypatch.setattr(ssh.time, "sleep", lambda d: None)

    made = []

    def factory():
        fake = AlwaysFailsClient()
        made.append(fake)
        return fake

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)

    with pytest.raises(ConnectionError):
        ssh.SSHClient("h", "u", "p").connect(retries=2)
    assert made[0].attempts == 2


def test_connect_does_not_sleep_after_the_final_failed_attempt(paramiko_clients, monkeypatch):
    sleeps = []
    monkeypatch.setattr(ssh.time, "sleep", lambda d: sleeps.append(d))

    made = []

    def factory():
        fake = AlwaysFailsClient()
        made.append(fake)
        return fake

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)

    with pytest.raises(ConnectionError):
        ssh.SSHClient("h", "u", "p").connect(retries=3, retry_delay=9.0)
    assert sleeps == [9.0, 9.0]
    assert made[0].attempts == 3


# --------------------------------------------------------------------------
# disconnect()
# --------------------------------------------------------------------------


def test_disconnect_closes_the_paramiko_client_and_resets_it(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.disconnect()
    assert fake.closed is True
    assert client._client is None


def test_disconnect_is_a_noop_before_connecting(paramiko_clients):
    client = ssh.SSHClient("h", "u", "p")
    client.disconnect()
    assert client._client is None
    assert paramiko_clients == []


# --------------------------------------------------------------------------
# run() / run_out() / run_sudo()
# --------------------------------------------------------------------------


def test_run_returns_decoded_and_stripped_stdout_stderr_and_exit_code(paramiko_clients):
    client, fake = connected(paramiko_clients)
    fake.exec_results = [("  hello world \n", "\npermission denied\n", 7)]
    out, err, code = client.run("ls -la")
    assert out == "hello world"
    assert err == "permission denied"
    assert code == 7


def test_run_passes_command_and_default_timeout_to_exec_command(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.run("id")
    assert fake.exec_calls == [("id", 30)]


def test_run_passes_explicit_timeout_through_to_exec_command(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.run("sleep 5", timeout=1)
    assert fake.exec_calls == [("sleep 5", 1)]


def test_run_propagates_socket_timeout_from_exec_command(paramiko_clients):
    client, fake = connected(paramiko_clients)
    fake.exec_error = socket.timeout("timed out")
    with pytest.raises(socket.timeout):
        client.run("sleep 100", timeout=1)


def test_run_out_returns_only_stdout(paramiko_clients):
    client, fake = connected(paramiko_clients)
    fake.exec_results = [("5.15.0", "warn", 0)]
    assert client.run_out("uname -r") == "5.15.0"


def test_run_out_forwards_timeout_to_run(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.run_out("whoami", timeout=5)
    assert fake.exec_calls == [("whoami", 5)]


def test_run_sudo_pipes_the_password_into_sudo_dash_s(paramiko_clients):
    client, fake = connected(paramiko_clients, password="hunter2")
    fake.exec_results = [("root", "", 0)]
    client.run_sudo("cat /etc/shadow")
    assert fake.exec_calls[0][0] == "echo 'hunter2' | sudo -S cat /etc/shadow"


def test_run_sudo_returns_the_wrapped_command_results(paramiko_clients):
    client, fake = connected(paramiko_clients, password="pw")
    fake.exec_results = [("secret", "", 0)]
    assert client.run_sudo("whoami") == ("secret", "", 0)


def test_run_sudo_forwards_timeout(paramiko_clients):
    client, fake = connected(paramiko_clients, password="pw")
    client.run_sudo("id", timeout=7)
    assert fake.exec_calls[0][1] == 7


# --------------------------------------------------------------------------
# upload() / download() / get_sftp()
# --------------------------------------------------------------------------


def test_upload_calls_sftp_put_with_local_then_remote_path(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.upload("/tmp/local.bin", "/remote/dest.bin")
    assert fake.sftp.put_calls == [("/tmp/local.bin", "/remote/dest.bin")]


def test_upload_closes_the_sftp_handle(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.upload("/tmp/a", "/tmp/b")
    assert fake.sftp.closed is True


def test_download_calls_sftp_get_with_remote_then_local_path(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.download("/remote/src.bin", "/tmp/local.bin")
    assert fake.sftp.get_calls == [("/remote/src.bin", "/tmp/local.bin")]


def test_download_closes_the_sftp_handle(paramiko_clients):
    client, fake = connected(paramiko_clients)
    client.download("/remote/src.bin", "/tmp/local.bin")
    assert fake.sftp.closed is True


def test_get_sftp_returns_the_opened_sftp_handle(paramiko_clients):
    client, fake = connected(paramiko_clients)
    assert client.get_sftp() is fake.sftp


# --------------------------------------------------------------------------
# context manager
# --------------------------------------------------------------------------


def test_context_manager_connects_on_enter_and_disconnects_on_exit(paramiko_clients):
    with ssh.SSHClient("h", "u", "p") as client:
        assert isinstance(client, ssh.SSHClient)
        assert client._client is paramiko_clients[0]
    assert paramiko_clients[0].closed is True
    assert client._client is None


def test_context_manager_disconnects_even_when_the_body_raises(paramiko_clients):
    client = None
    with pytest.raises(RuntimeError):
        with ssh.SSHClient("h", "u", "p") as client:
            raise RuntimeError("boom")
    assert client._client is None
    assert paramiko_clients[0].closed is True


# --------------------------------------------------------------------------
# test_connection()
# --------------------------------------------------------------------------


class FakeSocketCM:
    def __init__(self):
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *_):
        self.exited = True
        return False


def test_test_connection_returns_true_when_socket_connects(monkeypatch):
    created = []

    def fake_create_connection(address, timeout=None):
        cm = FakeSocketCM()
        created.append((address, timeout, cm))
        return cm

    monkeypatch.setattr(ssh.socket, "create_connection", fake_create_connection)
    assert ssh.test_connection("10.0.0.1", 2222, timeout=4) is True
    address, timeout, cm = created[0]
    assert address == ("10.0.0.1", 2222)
    assert timeout == 4
    assert cm.entered is True and cm.exited is True


def test_test_connection_defaults_to_port_22_and_three_second_timeout(monkeypatch):
    seen = []
    monkeypatch.setattr(
        ssh.socket,
        "create_connection",
        lambda a, timeout=None: seen.append((a, timeout)) or FakeSocketCM(),
    )
    ssh.test_connection("h")
    assert seen == [(("h", 22), 3)]


def test_test_connection_returns_false_on_connection_refused(monkeypatch):
    monkeypatch.setattr(
        ssh.socket,
        "create_connection",
        lambda a, timeout=None: (_ for _ in ()).throw(ConnectionRefusedError()),
    )
    assert ssh.test_connection("127.0.0.1") is False


def test_test_connection_returns_false_on_socket_timeout(monkeypatch):
    monkeypatch.setattr(
        ssh.socket,
        "create_connection",
        lambda a, timeout=None: (_ for _ in ()).throw(socket.timeout()),
    )
    assert ssh.test_connection("127.0.0.1") is False


def test_test_connection_returns_false_on_generic_os_error(monkeypatch):
    monkeypatch.setattr(
        ssh.socket,
        "create_connection",
        lambda a, timeout=None: (_ for _ in ()).throw(OSError("unreachable")),
    )
    assert ssh.test_connection("127.0.0.1") is False


def test_test_connection_propagates_unexpected_exceptions(monkeypatch):
    monkeypatch.setattr(
        ssh.socket,
        "create_connection",
        lambda a, timeout=None: (_ for _ in ()).throw(ValueError("weird")),
    )
    with pytest.raises(ValueError):
        ssh.test_connection("127.0.0.1")
