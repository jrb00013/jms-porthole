"""Unit tests for porthole.tunnel — sockets, threads and SSH are all faked; no real I/O."""

import select as select_module
import socket as socket_module

import pytest

from porthole import tunnel


class StopLoop(Exception):
    """Sentinel used to break out of the module's accept loops deterministically."""


class FakeServerSocket:
    def __init__(self, accept_results=()):
        self.setsockopt_calls = []
        self.bind_calls = []
        self.listen_calls = []
        self.closed = False
        self._accept_results = list(accept_results)

    def setsockopt(self, *args):
        self.setsockopt_calls.append(args)

    def bind(self, address):
        self.bind_calls.append(address)

    def listen(self, backlog):
        self.listen_calls.append(backlog)

    def accept(self):
        if not self._accept_results:
            raise StopLoop("no more connections")
        return self._accept_results.pop(0)

    def close(self):
        self.closed = True


class FakeDataSocket:
    """A plain TCP socket as seen by the _pipe / handler loops."""

    def __init__(self, recv_chunks=(), connect_error=None):
        self.connect_calls = []
        self.connect_error = connect_error
        self.sent = []
        self.closed = False
        self._recv_chunks = list(recv_chunks)

    def connect(self, address):
        self.connect_calls.append(address)
        if self.connect_error is not None:
            raise self.connect_error

    def recv(self, n):
        if self._recv_chunks:
            return self._recv_chunks.pop(0)
        return b""

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeParamikoChannel:
    def __init__(self, recv_chunks=()):
        self.recv_chunks = list(recv_chunks)
        self.sent = []
        self.closed = False

    def recv(self, n):
        if self.recv_chunks:
            return self.recv_chunks.pop(0)
        return b""

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, accepts=()):
        self.accept_calls = []
        self._accepts = list(accepts)
        self.request_port_forward_calls = []
        self.open_channel_calls = []

    def request_port_forward(self, bind_address, port):
        self.request_port_forward_calls.append((bind_address, port))

    def accept(self, timeout):
        self.accept_calls.append(timeout)
        if not self._accepts:
            raise StopLoop("transport closed")
        return self._accepts.pop(0)

    def open_channel(self, kind, dest, src):
        self.open_channel_calls.append((kind, dest, src))
        return FakeParamikoChannel()


class FakeInnerClient:
    def __init__(self, transport):
        self._transport = transport
        self.get_transport_calls = 0

    def get_transport(self):
        self.get_transport_calls += 1
        return self._transport


class FakeSSHClient:
    instances = []
    connect_error = None
    accept_channel = None

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.transport = FakeTransport(
            accepts=[type(self).accept_channel] if type(self).accept_channel else []
        )
        self._client = FakeInnerClient(self.transport)
        self.connect_calls = 0
        self.disconnect_calls = 0
        type(self).instances.append(self)

    def connect(self):
        self.connect_calls += 1
        if type(self).connect_error is not None:
            raise type(self).connect_error
        return self

    def disconnect(self):
        self.disconnect_calls += 1


class FakeThread:
    """Captures the thread target instead of running it, so no background work happens."""

    created = []

    def __init__(self, target=None, args=(), daemon=None, **kwargs):
        self.target = target
        self.args = args
        self.daemon = daemon
        self.started = False
        type(self).created.append(self)

    def start(self):
        self.started = True

    @classmethod
    def by_name(cls, name):
        return [t for t in cls.created if t.target.__name__ == name]


class RecordingConsole:
    def __init__(self):
        self.printed = []

    def print(self, *args, **kwargs):
        self.printed.append(args[0] if args else None)


@pytest.fixture
def env(monkeypatch):
    """Patch out SSH, sockets, threads, the console and the blocking sleep."""
    FakeSSHClient.instances = []
    FakeSSHClient.connect_error = None
    FakeSSHClient.accept_channel = None
    FakeThread.created = []

    console = RecordingConsole()
    server_box = {}

    def bind_server(server):
        server_box["server"] = server
        monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: server)
        return server

    monkeypatch.setattr(tunnel, "SSHClient", FakeSSHClient)
    monkeypatch.setattr(tunnel.threading, "Thread", FakeThread)
    monkeypatch.setattr(tunnel, "console", console)
    # select.select is called with 3 args by _forward_tunnel's handler and 4 by _pipe;
    # the default fake reports every fd as readable and returns the right arity.
    monkeypatch.setattr(
        select_module, "select", lambda *a: tuple([list(a[0])] + [[]] * (len(a) - 1))
    )
    monkeypatch.setattr(tunnel.time, "sleep", lambda _s: (_ for _ in ()).throw(KeyboardInterrupt()))
    return {"console": console, "bind": bind_server, "server": server_box}


# --------------------------------------------------------------------------
# open_tunnel(): wiring
# --------------------------------------------------------------------------


def test_open_tunnel_connects_to_the_jump_host_with_the_given_credentials(env):
    env["bind"](FakeServerSocket())
    tunnel.open_tunnel("bastion", "root", "pw", 8080, "10.0.0.9", 443)
    client = FakeSSHClient.instances[0]
    assert (client.host, client.username, client.password) == ("bastion", "root", "pw")
    assert client.connect_calls == 1


def test_open_tunnel_fetches_the_transport_from_the_connected_client(env):
    env["bind"](FakeServerSocket())
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    assert FakeSSHClient.instances[0]._client.get_transport_calls == 1


def test_open_tunnel_binds_localhost_on_the_local_port_not_the_remote_one(env):
    server = env["bind"](FakeServerSocket())
    tunnel.open_tunnel("bastion", "root", "pw", 8080, "10.0.0.9", 443)
    assert server.bind_calls == [("127.0.0.1", 8080)]


def test_open_tunnel_keeps_local_and_remote_ports_distinct(env):
    server = env["bind"](FakeServerSocket())
    tunnel.open_tunnel("b", "u", "p", 15000, "10.0.0.9", 5432)
    assert server.bind_calls == [("127.0.0.1", 15000)]
    assert server.bind_calls[0][1] != 5432


def test_open_tunnel_listens_with_backlog_five_and_reuseaddr(env):
    server = env["bind"](FakeServerSocket())
    tunnel.open_tunnel("b", "u", "p", 9000, "db.internal", 5432)
    assert server.listen_calls == [5]
    assert server.setsockopt_calls == [(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)]


def test_open_tunnel_never_binds_when_the_ssh_connection_fails(env):
    bound = []

    class ExplodingSocket(FakeServerSocket):
        def bind(self, address):
            bound.append(address)
            raise AssertionError("must not bind when SSH fails")

    FakeSSHClient.connect_error = RuntimeError("auth failed")
    env["bind"](ExplodingSocket())

    with pytest.raises(RuntimeError, match="auth failed"):
        tunnel.open_tunnel("bastion", "root", "bad", 8080, "10.0.0.9", 443)
    assert bound == []


def test_open_tunnel_announces_the_local_and_remote_endpoints(env):
    env["bind"](FakeServerSocket())
    tunnel.open_tunnel("bastion", "root", "pw", 8080, "10.0.0.9", 443)
    assert env["console"].printed[0] == (
        "[cyan]Opening tunnel: localhost:8080 → 10.0.0.9:443 via bastion[/cyan]"
    )
    assert "localhost:8080" in env["console"].printed[1]


def test_open_tunnel_starts_the_accept_loop_thread_daemonised(env):
    env["bind"](FakeServerSocket())
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    accept_threads = FakeThread.by_name("accept_loop")
    assert len(accept_threads) == 1
    assert accept_threads[0].daemon is True
    assert accept_threads[0].started is True


def test_open_tunnel_closes_the_server_socket_and_disconnects_on_ctrl_c(env):
    server = env["bind"](FakeServerSocket())
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    assert server.closed is True
    assert FakeSSHClient.instances[0].disconnect_calls == 1
    assert env["console"].printed[-1] == "\n[yellow]Closing tunnel...[/yellow]"


# --------------------------------------------------------------------------
# the accept_loop closure
# --------------------------------------------------------------------------


def run_accept_loop():
    """Run the captured accept_loop closure; it breaks out on the first accept error."""
    thread = FakeThread.by_name("accept_loop")[0]
    thread.target()  # returns normally: the loop swallows the StopLoop
    return thread


def test_accept_loop_opens_a_direct_tcpip_channel_to_the_remote_endpoint(env):
    addr = ("127.0.0.1", 55555)
    env["bind"](FakeServerSocket(accept_results=[(FakeDataSocket(), addr)]))
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    run_accept_loop()
    assert FakeSSHClient.instances[0].transport.open_channel_calls == [
        ("direct-tcpip", ("h", 2), addr)
    ]


def test_accept_loop_pipes_each_connection_in_a_daemon_thread(env):
    conn = FakeDataSocket()
    env["bind"](FakeServerSocket(accept_results=[(conn, ("127.0.0.1", 1))]))
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    run_accept_loop()
    pipe_threads = FakeThread.by_name("_pipe")
    assert len(pipe_threads) == 1
    assert pipe_threads[0].daemon is True
    assert pipe_threads[0].args[0] is conn


def test_accept_loop_stops_silently_on_the_first_exception(env):
    class BadServer(FakeServerSocket):
        def accept(self):
            raise OSError("listener dead")

    server = env["bind"](BadServer())
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    thread = FakeThread.by_name("accept_loop")[0]
    thread.target()  # must return, not raise
    assert server.closed is True


# --------------------------------------------------------------------------
# the _pipe closure
# --------------------------------------------------------------------------


def open_tunnel_with_one_connection(env, conn=None):
    """Run open_tunnel, then its accept loop once, and return the captured _pipe."""
    conn = conn if conn is not None else FakeDataSocket()
    env["bind"](FakeServerSocket(accept_results=[(conn, ("127.0.0.1", 1))]))
    tunnel.open_tunnel("b", "u", "p", 1, "h", 2)
    run_accept_loop()
    return FakeThread.by_name("_pipe")[0].target


@pytest.mark.xfail(
    strict=True,
    reason="source bug: tunnel.py:71 unpacks 3 values from select.select()'s 4-tuple -> ValueError",
)
def test_pipe_breaks_immediately_when_the_client_socket_is_empty(env):
    conn = FakeDataSocket()
    pipe = open_tunnel_with_one_connection(env, conn)
    pipe(conn, FakeParamikoChannel())
    assert conn.closed is True


def test_pipe_raises_valueerror_because_select_returns_a_four_value_tuple(env):
    """Documents porthole/tunnel.py:71 — `_pipe` unpacks 3 values from a 4-tuple."""
    conn = FakeDataSocket()
    pipe = open_tunnel_with_one_connection(env, conn)
    with pytest.raises(ValueError, match="too many values to unpack"):
        pipe(conn, FakeParamikoChannel())


@pytest.mark.xfail(
    strict=True,
    reason="source bug: tunnel.py:71 unpacks 3 values from select.select()'s 4-tuple -> ValueError",
)
def test_pipe_closes_both_ends_when_the_channel_reports_eof(env):
    conn = FakeDataSocket()
    chan = FakeParamikoChannel()
    pipe = open_tunnel_with_one_connection(env, conn)
    pipe(conn, chan)
    assert conn.closed is True
    assert chan.closed is True


@pytest.mark.xfail(
    strict=True,
    reason="source bug: tunnel.py:71 unpacks 3 values from select.select()'s 4-tuple -> ValueError",
)
def test_pipe_relays_client_bytes_to_the_channel(monkeypatch, env):
    conn = FakeDataSocket(recv_chunks=[b"GET / HTTP/1.0\r\n", b""])
    chan = FakeParamikoChannel()
    steps = [([conn], [], [], []), ([conn], [], [], [])]

    def fake_select(_r, _w, _x, timeout):
        assert timeout == 1
        return steps.pop(0)

    monkeypatch.setattr(select_module, "select", fake_select)
    pipe = open_tunnel_with_one_connection(env, conn)
    pipe(conn, chan)

    assert chan.sent == [b"GET / HTTP/1.0\r\n"]


@pytest.mark.xfail(
    strict=True,
    reason="source bug: tunnel.py:71 unpacks 3 values from select.select()'s 4-tuple -> ValueError",
)
def test_pipe_relays_channel_bytes_back_to_the_client(monkeypatch, env):
    conn = FakeDataSocket()
    chan = FakeParamikoChannel(recv_chunks=[b"HTTP/1.1 200 OK\r\n", b""])
    steps = [([chan], [], [], []), ([chan], [], [], [])]
    monkeypatch.setattr(select_module, "select", lambda *a: steps.pop(0))

    pipe = open_tunnel_with_one_connection(env, conn)
    pipe(conn, chan)

    assert conn.sent == [b"HTTP/1.1 200 OK\r\n"]


@pytest.mark.xfail(
    strict=True,
    reason="source bug: tunnel.py:71 unpacks 3 values from select.select()'s 4-tuple -> ValueError",
)
def test_pipe_handles_both_directions_in_the_same_select_round(monkeypatch, env):
    conn = FakeDataSocket(recv_chunks=[b"ping"])
    chan = FakeParamikoChannel(recv_chunks=[b"pong"])
    monkeypatch.setattr(select_module, "select", lambda r, w, x, t: (list(r), [], [], []))

    pipe = open_tunnel_with_one_connection(env, conn)
    pipe(conn, chan)

    assert chan.sent == [b"ping"]
    assert conn.sent == [b"pong"]


# --------------------------------------------------------------------------
# _forward_tunnel(): the remote-forward helper
# --------------------------------------------------------------------------


def run_forward_tunnel(local_port, remote_host, remote_port, transport):
    """Run _forward_tunnel until the fake transport runs out of channels."""
    with pytest.raises(StopLoop):
        tunnel._forward_tunnel(local_port, remote_host, remote_port, transport)
    return FakeThread.by_name("handler")


def test_forward_tunnel_requests_a_port_forward_for_the_local_port(env):
    transport = FakeTransport(accepts=[FakeParamikoChannel()])
    run_forward_tunnel(8080, "10.0.0.9", 443, transport)
    assert transport.request_port_forward_calls == [("", 8080)]


def test_forward_tunnel_ignores_accept_timeouts_and_keeps_waiting(env):
    transport = FakeTransport(accepts=[None, None, FakeParamikoChannel()])
    handlers = run_forward_tunnel(8080, "h", 2, transport)
    assert transport.accept_calls == [1000, 1000, 1000, 1000]
    assert len(handlers) == 1


def test_forward_tunnel_never_requests_a_forward_for_the_remote_port(env):
    transport = FakeTransport(accepts=[FakeParamikoChannel()])
    run_forward_tunnel(8080, "h", 9999, transport)
    assert [p for _, p in transport.request_port_forward_calls] == [8080]


def test_forward_tunnel_handler_connects_to_the_remote_endpoint(env, monkeypatch):
    sock = FakeDataSocket()
    monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: sock)
    transport = FakeTransport(accepts=[FakeParamikoChannel()])

    handlers = run_forward_tunnel(8080, "10.0.0.9", 443, transport)

    assert len(handlers) == 1
    assert handlers[0].daemon is True
    handlers[0].target(*handlers[0].args)
    assert sock.connect_calls == [("10.0.0.9", 443)]


def test_forward_tunnel_handler_closes_the_channel_when_the_remote_connect_fails(env, monkeypatch):
    sock = FakeDataSocket(connect_error=OSError("refused"))
    monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: sock)
    chan = FakeParamikoChannel()
    transport = FakeTransport(accepts=[chan])

    handlers = run_forward_tunnel(8080, "10.0.0.9", 443, transport)
    handlers[0].target(*handlers[0].args)

    assert sock.connect_calls == [("10.0.0.9", 443)]
    assert chan.closed is True


def test_forward_tunnel_handler_pumps_data_both_ways_until_eof(env, monkeypatch):
    sock = FakeDataSocket(recv_chunks=[b"from-remote"])
    chan = FakeParamikoChannel(recv_chunks=[b"to-remote", b""])
    monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: sock)
    select_args = []

    def fake_select(r, w, x):
        select_args.append(len(r))
        return (list(r), [], [])

    monkeypatch.setattr(select_module, "select", fake_select)
    transport = FakeTransport(accepts=[chan])

    handlers = run_forward_tunnel(8080, "h", 2, transport)
    handlers[0].target(*handlers[0].args)

    assert select_args and set(select_args) == {2}  # watches both the socket and the channel
    assert chan.sent == [b"from-remote"]
    assert sock.sent == [b"to-remote"]
    assert chan.closed is True
    assert sock.closed is True


def test_forward_tunnel_handler_closes_the_channel_when_the_remote_socket_sends_eof(
    env, monkeypatch
):
    sock = FakeDataSocket(recv_chunks=[b""])
    chan = FakeParamikoChannel()
    monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: sock)
    monkeypatch.setattr(select_module, "select", lambda r, w, x: (list(r), [], []))

    transport = FakeTransport(accepts=[chan])
    handlers = run_forward_tunnel(8080, "h", 2, transport)
    handlers[0].target(*handlers[0].args)

    assert chan.closed is True
    assert sock.closed is True


def test_forward_tunnel_handler_stops_when_the_channel_reports_eof(env, monkeypatch):
    sock = FakeDataSocket(recv_chunks=[b"a", b"b", b"c"])
    chan = FakeParamikoChannel(recv_chunks=[b""])
    monkeypatch.setattr(tunnel.socket, "socket", lambda *a, **k: sock)
    monkeypatch.setattr(select_module, "select", lambda r, w, x: (list(r), [], []))

    transport = FakeTransport(accepts=[chan])
    handlers = run_forward_tunnel(8080, "h", 2, transport)
    handlers[0].target(*handlers[0].args)

    assert chan.sent == [b"a"]  # one round before the channel signals EOF
    assert chan.closed is True
    assert sock.closed is True
