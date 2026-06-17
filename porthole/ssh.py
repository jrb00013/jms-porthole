import paramiko
import socket
from contextlib import contextmanager
from typing import Optional


class SSHClient:
    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> "SSHClient":
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=10,
        )
        return self

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None

    def run(self, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
        """Run a command, return (stdout, stderr, exit_code)."""
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return stdout.read().decode().strip(), stderr.read().decode().strip(), exit_code

    def run_out(self, cmd: str, timeout: int = 30) -> str:
        """Run command and return stdout, ignoring errors."""
        out, _, _ = self.run(cmd, timeout=timeout)
        return out

    def run_sudo(self, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
        """Run a command with sudo using the stored password."""
        return self.run(f"echo '{self.password}' | sudo -S {cmd}", timeout=timeout)

    def get_sftp(self):
        return self._client.open_sftp()

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_):
        self.disconnect()


def test_connection(host: str, port: int = 22, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
