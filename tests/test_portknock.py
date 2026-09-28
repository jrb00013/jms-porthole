"""Unit tests for porthole.portknock — asserts the exact knock sequence, no real sockets."""

import socket

import pytest

from porthole import portknock


class FakeSocket:
    """Records the socket calls knock() makes; never touches the network."""

    def __init__(self, family, kind, factory, fail_on=None):
        self.family = family
        self.kind = kind
        self.factory = factory
        self.timeouts = []
        self.connect_ex_calls = []
        self.sendto_calls = []
        self.closed = False
        self._fail_on = fail_on

    def settimeout(self, value):
        self.timeouts.append(value)

    def setsockopt(self, *args):
        pass

    def connect_ex(self, address):
        self.connect_ex_calls.append(address)
        if self._fail_on is not None:
            raise self._fail_on
        return 0

    def sendto(self, data, address):
        self.sendto_calls.append((data, address))
        if self._fail_on is not None:
            raise self._fail_on

    def close(self):
        self.closed = True


class SocketFactory:
    def __init__(self, fail_on=None, raise_on_construct=None):
        self.sockets = []
        self.fail_on = fail_on
        self.raise_on_construct = raise_on_construct

    def __call__(self, family, kind, *args):
        if self.raise_on_construct is not None:
            raise self.raise_on_construct
        s = FakeSocket(family, kind, self, fail_on=self.fail_on)
        self.sockets.append(s)
        return s

    @property
    def knock_targets(self):
        """Flatten connect_ex/sendto targets in the order knock() issued them."""
        targets = []
        for s in self.sockets:
            targets.extend(s.connect_ex_calls)
            targets.extend(addr for _, addr in s.sendto_calls)
        return targets


@pytest.fixture
def sock_factory(monkeypatch):
    def install(fail_on=None, raise_on_construct=None):
        factory = SocketFactory(fail_on=fail_on, raise_on_construct=raise_on_construct)
        monkeypatch.setattr(portknock.socket, "socket", factory)
        return factory

    return install


@pytest.fixture
def no_sleep(monkeypatch):
    calls = []
    monkeypatch.setattr(portknock.time, "sleep", lambda d: calls.append(d))
    return calls


# --- TCP sequence -------------------------------------------------------------


def test_knock_tcp_connects_to_ports_in_given_order(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [1111, 2222, 3333])
    assert factory.knock_targets == [
        ("10.0.0.5", 1111),
        ("10.0.0.5", 2222),
        ("10.0.0.5", 3333),
    ]


def test_knock_tcp_uses_stream_sockets(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [7000])
    assert len(factory.sockets) == 1
    assert factory.sockets[0].family == socket.AF_INET
    assert factory.sockets[0].kind == socket.SOCK_STREAM


def test_knock_tcp_sets_three_tenths_second_timeout(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [7000])
    assert factory.sockets[0].timeouts == [0.3]


def test_knock_tcp_closes_every_socket_it_opens(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [1, 2, 3])
    assert len(factory.sockets) == 3
    assert all(s.closed for s in factory.sockets)


def test_knock_tcp_sends_no_payload(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [7000])
    assert factory.sockets[0].sendto_calls == []


def test_knock_single_port_makes_exactly_one_connection(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [8080])
    assert len(factory.sockets) == 1


def test_knock_empty_port_list_opens_no_sockets(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [])
    assert factory.sockets == []


# --- UDP sequence -------------------------------------------------------------


def test_knock_udp_sends_null_byte_to_each_port(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [100, 200], protocol="udp")
    assert factory.sockets[0].sendto_calls == [(b"\x00", ("10.0.0.5", 100))]
    assert factory.sockets[1].sendto_calls == [(b"\x00", ("10.0.0.5", 200))]


def test_knock_udp_uses_datagram_sockets(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [100], protocol="udp")
    assert factory.sockets[0].kind == socket.SOCK_DGRAM


def test_knock_udp_does_not_call_connect_ex(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [100], protocol="udp")
    assert factory.sockets[0].connect_ex_calls == []


def test_knock_udp_does_not_set_timeout(sock_factory, no_sleep):
    """Only the TCP branch calls settimeout; the UDP branch must not."""
    factory = sock_factory()
    portknock.knock("10.0.0.5", [100], protocol="udp")
    assert factory.sockets[0].timeouts == []


# --- delays -------------------------------------------------------------------


def test_knock_sleeps_once_per_port_with_given_delay(sock_factory, no_sleep):
    portknock.knock("10.0.0.5", [1, 2, 3, 4], delay=0.25)
    assert no_sleep == [0.25, 0.25, 0.25, 0.25]


def test_knock_default_delay_is_a_tenth_of_a_second(sock_factory, no_sleep):
    portknock.knock("10.0.0.5", [1, 2])
    assert no_sleep == [0.1, 0.1]


def test_knock_still_sleeps_when_port_list_is_empty(sock_factory, no_sleep):
    portknock.knock("10.0.0.5", [], delay=0.5)
    assert no_sleep == []


# --- error resilience ---------------------------------------------------------


def test_knock_continues_sequence_after_connection_error(sock_factory, no_sleep):
    factory = sock_factory(fail_on=OSError("network unreachable"))
    portknock.knock("10.0.0.5", [1, 2, 3])
    assert factory.knock_targets == [("10.0.0.5", 1), ("10.0.0.5", 2), ("10.0.0.5", 3)]


def test_knock_continues_sequence_after_socket_construct_error(sock_factory, no_sleep):
    factory = sock_factory(raise_on_construct=OSError("cannot allocate socket"))
    portknock.knock("10.0.0.5", [1, 2])
    assert factory.sockets == []
    assert no_sleep == [0.1, 0.1]


def test_knock_survives_connection_refused(sock_factory, no_sleep):
    factory = sock_factory(fail_on=ConnectionRefusedError())
    portknock.knock("10.0.0.5", [22, 80])
    assert len(factory.knock_targets) == 2


def test_knock_unknown_protocol_opens_no_sockets_but_still_delays(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("10.0.0.5", [1, 2], protocol="sctp")
    assert factory.sockets == []
    assert no_sleep == [0.1, 0.1]


def test_knock_mixed_hostname_and_ip_targets_are_passed_through(sock_factory, no_sleep):
    factory = sock_factory()
    portknock.knock("knock.example.com", [9])
    assert factory.knock_targets == [("knock.example.com", 9)]


# --- console output -----------------------------------------------------------


def test_knock_prints_summary_line_with_ports(monkeypatch, sock_factory, no_sleep):
    lines = []
    monkeypatch.setattr(
        portknock.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a))
    )
    portknock.knock("10.0.0.5", [1, 2, 3])
    joined = "\n".join(lines)
    assert "1" in joined and "2" in joined and "3" in joined
    assert any("Knock sequence sent" in l for l in lines)


def test_knock_prints_one_progress_line_per_port(monkeypatch, sock_factory, no_sleep):
    lines = []
    monkeypatch.setattr(
        portknock.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a))
    )
    portknock.knock("10.0.0.5", [1, 2], protocol="udp")
    progress = [l for l in lines if "/udp" in l]
    assert len(progress) == 2
    assert "1/udp" in progress[0]
    assert "2/udp" in progress[1]
