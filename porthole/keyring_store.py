"""
Optional system keyring integration for storing credentials securely.
Falls back to the JSON config if keyring is not available.
"""
from rich.console import Console

console = Console()

try:
    import keyring as _keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False

SERVICE = "jms-porthole"


def store_password(alias: str, username: str, password: str):
    if not HAS_KEYRING:
        console.print("[yellow]keyring not installed — password stored in plain config[/yellow]")
        return False
    _keyring.set_password(SERVICE, f"{alias}:{username}", password)
    return True


def get_password(alias: str, username: str) -> str | None:
    if not HAS_KEYRING:
        return None
    return _keyring.get_password(SERVICE, f"{alias}:{username}")


def delete_password(alias: str, username: str):
    if not HAS_KEYRING:
        return
    try:
        _keyring.delete_password(SERVICE, f"{alias}:{username}")
    except Exception:
        pass
