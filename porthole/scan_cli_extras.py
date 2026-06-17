"""
Extra scan CLI options wired into the scan command:
 --preset web|db|remote|devops|all
"""
# This module is intentionally thin — it just re-exports helpers
# so cli.py can import from one place.
from .scanner import resolve_port_preset, PORT_RANGE_PRESETS

__all__ = ["resolve_port_preset", "PORT_RANGE_PRESETS"]
