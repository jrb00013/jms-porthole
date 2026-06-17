import paramiko
import socket
import time
from contextlib import contextmanager
from typing import Optional


class SSHClient:
    def __init__(self, host: str, username: str, password: str = None,
                 key_path: str = None, port: int = 22, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self, retries: int = 3, retry_delay: float = 2.0) -> "SSHClient":
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        last_err = None
        for attempt in range(retries):
            try:
                kwargs = dict(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    timeout=self.timeout,
                )
                if self.key_path:
                    kwargs["key_filename"] = self.key_path
                elif self.password:
                    kwargs["password"] = self.password

                self._client.connect(**kwargs)
                return self
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    time.sleep(retry_delay)

        raise ConnectionError(f"Failed to connect to {self.host}:{self.port} — {last_err}")

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
        out, _, _ = self.run(cmd, timeout=timeout)
        return out

    def run_sudo(self, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
        return self.run(f"echo '{self.password}' | sudo -S {cmd}", timeout=timeout)

    def upload(self, local_path: str, remote_path: str):
        sftp = self._client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()

    def download(self, remote_path: str, local_path: str):
        sftp = self._client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()

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
