"""
Deploy SSH public keys to remote authorized_keys.
"""
import os
from rich.console import Console
from .ssh import SSHClient

console = Console()


def deploy_key(host: str, username: str, password: str,
               pubkey_path: str, comment: str = None) -> bool:
    pubkey_path = os.path.expanduser(pubkey_path)
    if not os.path.isfile(pubkey_path):
        raise FileNotFoundError(f"Public key not found: {pubkey_path}")

    with open(pubkey_path) as f:
        pubkey = f.read().strip()

    if not pubkey.startswith(("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-")):
        raise ValueError(f"Invalid public key format in {pubkey_path}")

    with SSHClient(host, username, password) as ssh:
        ssh.run_out("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        existing = ssh.run_out("cat ~/.ssh/authorized_keys 2>/dev/null")

        if pubkey.split()[1] in existing.replace("\n", " "):
            console.print(f"[yellow]Key already present on {host}[/yellow]")
            return False

        tag = comment or f"porthole-{username}@{host}"
        line = f"{pubkey} {tag}" if tag not in pubkey else pubkey
        ssh.run_out(f"echo '{line}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")

    console.print(f"[green]Deployed {pubkey_path} to {username}@{host}[/green]")
    return True


def list_remote_keys(host: str, username: str, password: str) -> list[str]:
    with SSHClient(host, username, password) as ssh:
        raw = ssh.run_out("cat ~/.ssh/authorized_keys 2>/dev/null")
    return [l.strip() for l in raw.splitlines() if l.strip()]


def print_remote_keys(host: str, keys: list[str]):
    if not keys:
        console.print(f"[dim]No authorized keys on {host}[/dim]")
        return
    console.print(f"[bold]Authorized keys on {host}:[/bold]")
    for i, k in enumerate(keys, 1):
        parts = k.split()
        key_type = parts[0] if parts else "?"
        comment = parts[-1] if len(parts) > 2 else "(no comment)"
        console.print(f"  {i}. [{key_type}] {comment}")
