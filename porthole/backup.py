"""
Remote backup — tarball a remote directory and download it.
"""
import os
import time
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, FileSizeColumn
from .ssh import SSHClient

console = Console()


def backup_remote(host: str, username: str, password: str,
                  remote_path: str, output: str = None,
                  exclude: list[str] = None) -> str:
    remote_path = remote_path.rstrip("/")
    if not output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(remote_path) or "backup"
        output = f"jms_backup_{host}_{basename}_{ts}.tar.gz"

    output = os.path.expanduser(output)
    exclude_args = ""
    if exclude:
        exclude_args = " ".join(f"--exclude='{e}'" for e in exclude)

    with SSHClient(host, username, password) as ssh:
        size_raw = ssh.run_out(f"du -sb {remote_path} 2>/dev/null | awk '{{print $1}}'")
        remote_size = int(size_raw) if size_raw.isdigit() else 0

        console.print(f"[cyan]Creating backup of {host}:{remote_path}...[/cyan]")
        tar_cmd = f"tar czf - {exclude_args} -C $(dirname {remote_path}) $(basename {remote_path}) 2>/dev/null"

        transport = ssh._client.get_transport()
        channel = transport.open_session()
        channel.exec_command(tar_cmd)

        received = 0
        with open(output, "wb") as f, Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            FileSizeColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Downloading", total=remote_size or None)
            while True:
                data = channel.recv(65536)
                if not data:
                    break
                f.write(data)
                received += len(data)
                progress.update(task, completed=received)

        channel.recv_exit_status()

    local_size = os.path.getsize(output)
    console.print(f"[green]Backup saved: {output} ({local_size:,} bytes)[/green]")
    return output


def list_backups(directory: str = ".") -> list[dict]:
    directory = os.path.expanduser(directory)
    backups = []
    for f in os.listdir(directory):
        if f.startswith("jms_backup_") and f.endswith(".tar.gz"):
            path = os.path.join(directory, f)
            backups.append({
                "file": f,
                "path": path,
                "size": os.path.getsize(path),
                "mtime": os.path.getmtime(path),
            })
    return sorted(backups, key=lambda x: x["mtime"], reverse=True)
