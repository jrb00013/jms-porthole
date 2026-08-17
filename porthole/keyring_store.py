"""
OS keyring integration for storing credentials securely.

This is the preferred credential path: config.py and spray.py store/resolve
passwords through the OS keyring (Secret Service / macOS Keychain / Windows
Credential Locker, whatever `keyring` resolves to on this platform) keyed by
`(alias, username)`. Only when the keyring backend is unavailable does the
caller fall back to storing a password in plaintext in
~/.config/jms/hosts.json — and that fallback is expected to warn the user
loudly (see config.py) rather than happen silently.
"""
from rich.console import Console

console = Console()

try:
    import keyring as _keyring
    from keyring.errors import KeyringError, NoKeyringError
    HAS_KEYRING = True
except ImportError:
    _keyring = None
    KeyringError = NoKeyringError = Exception
    HAS_KEYRING = False

SERVICE = "jms-porthole"


def is_available() -> bool:
    """Return True if a real (non-null) keyring backend is usable right now."""
    if not HAS_KEYRING:
        return False
    try:
        backend = _keyring.get_keyring()
    except Exception:
        return False
    # keyring falls back to a "backends.fail" module when nothing real is configured.
    return "backends.fail" not in type(backend).__module__


def store_password(alias: str, username: str, password: str) -> bool:
    """Store a password in the OS keyring. Returns True on success."""
    if not is_available():
        console.print("[yellow]No usable OS keyring backend — password will fall back to plain config[/yellow]")
        return False
    try:
        _keyring.set_password(SERVICE, f"{alias}:{username}", password)
        return True
    except (KeyringError, NoKeyringError, Exception) as e:
        console.print(f"[yellow]Keyring store failed ({e}) — falling back to plain config[/yellow]")
        return False


def get_password(alias: str, username: str) -> str | None:
    """Fetch a password from the OS keyring, or None if unavailable/not found."""
    if not is_available():
        return None
    try:
        return _keyring.get_password(SERVICE, f"{alias}:{username}")
    except Exception:
        return None


def delete_password(alias: str, username: str) -> bool:
    if not HAS_KEYRING:
        return False
    try:
        _keyring.delete_password(SERVICE, f"{alias}:{username}")
        return True
    except Exception:
        return False
