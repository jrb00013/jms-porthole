"""
File transfer — upload/download files to/from remote hosts via SFTP.
"""
import os
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, FileSizeColumn, TransferSpeedColumn, TimeRemainingColumn
from .ssh import SSHClient

console = Console()


def _make_progress():
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    )


def upload_file(host: str, username: str, password: str, local_path: str, remote_path: str):
    local_path = os.path.expanduser(local_path)
    file_size = os.path.getsize(local_path)

    with SSHClient(host, username, password) as ssh:
        sftp = ssh.get_sftp()

        with _make_progress() as progress:
            task = progress.add_task(f"Uploading {os.path.basename(local_path)}", total=file_size)

            def callback(transferred, total):
                progress.update(task, completed=transferred)

            sftp.put(local_path, remote_path, callback=callback)
        sftp.close()

    console.print(f"[green]Uploaded to {host}:{remote_path}[/green]")


def download_file(host: str, username: str, password: str, remote_path: str, local_path: str):
    local_path = os.path.expanduser(local_path)

    with SSHClient(host, username, password) as ssh:
        sftp = ssh.get_sftp()
        stat = sftp.stat(remote_path)
        file_size = stat.st_size or 0

        with _make_progress() as progress:
            task = progress.add_task(f"Downloading {os.path.basename(remote_path)}", total=file_size)

            def callback(transferred, total):
                progress.update(task, completed=transferred)

            sftp.get(remote_path, local_path, callback=callback)
        sftp.close()

    console.print(f"[green]Downloaded to {local_path}[/green]")


def list_remote_dir(host: str, username: str, password: str, remote_path: str = "."):
    from rich.table import Table
    import stat as stat_mod
    from datetime import datetime

    with SSHClient(host, username, password) as ssh:
        sftp = ssh.get_sftp()
        entries = sftp.listdir_attr(remote_path)
        sftp.close()

    table = Table(title=f"{host}:{remote_path}", border_style="cyan")
    table.add_column("Name", style="bold cyan")
    table.add_column("Size", justify="right")
    table.add_column("Modified")
    table.add_column("Perms")

    dirs, files = [], []
    for e in entries:
        (dirs if stat_mod.S_ISDIR(e.st_mode) else files).append(e)

    for e in sorted(dirs, key=lambda x: x.filename) + sorted(files, key=lambda x: x.filename):
        is_dir = stat_mod.S_ISDIR(e.st_mode)
        name = f"[bold blue]{e.filename}/[/bold blue]" if is_dir else e.filename
        size = "—" if is_dir else str(e.st_size)
        mtime = datetime.fromtimestamp(e.st_mtime).strftime("%Y-%m-%d %H:%M") if e.st_mtime else ""
        perms = oct(stat_mod.S_IMODE(e.st_mode))
        table.add_row(name, size, mtime, perms)

    console.print(table)
