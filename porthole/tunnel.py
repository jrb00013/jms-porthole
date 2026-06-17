import threading
import socket
import select
import time
from rich.console import Console
from rich.table import Table
from .ssh import SSHClient

console = Console()


def _forward_tunnel(local_port: int, remote_host: str, remote_port: int, transport):
    def handler(chan, origin, server):
        sock = socket.socket()
        try:
            sock.connect((remote_host, remote_port))
        except Exception as e:
            chan.close()
            return
        while True:
            r, _, _ = select.select([sock, chan], [], [])
            if sock in r:
                data = sock.recv(1024)
                if not data:
                    break
                chan.sendall(data)
            if chan in r:
                data = chan.recv(1024)
                if not data:
                    break
                sock.sendall(data)
        chan.close()
        sock.close()

    transport.request_port_forward("", local_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        t = threading.Thread(target=handler, args=(chan, None, None), daemon=True)
        t.start()


def open_tunnel(host: str, username: str, password: str,
                local_port: int, remote_host: str, remote_port: int):
    """Open a local port forward: localhost:local_port -> remote_host:remote_port via host."""
    console.print(f"[cyan]Opening tunnel: localhost:{local_port} → {remote_host}:{remote_port} via {host}[/cyan]")

    client = SSHClient(host, username, password).connect()
    transport = client._client.get_transport()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(5)

    console.print(f"[green]Tunnel open. Connect to localhost:{local_port}. Ctrl+C to close.[/green]")

    def accept_loop():
        while True:
            try:
                conn, addr = server.accept()
                chan = transport.open_channel("direct-tcpip", (remote_host, remote_port), addr)
                t = threading.Thread(target=_pipe, args=(conn, chan), daemon=True)
                t.start()
            except Exception:
                break

    def _pipe(conn, chan):
        while True:
            r, _, _ = select.select([conn, chan], [], [], 1)
            if conn in r:
                data = conn.recv(1024)
                if not data:
                    break
                chan.sendall(data)
            if chan in r:
                data = chan.recv(1024)
                if not data:
                    break
                conn.sendall(data)
        conn.close()
        chan.close()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Closing tunnel...[/yellow]")
        server.close()
        client.disconnect()
