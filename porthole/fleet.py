"""
Fleet-wide parallel execution — run one function across many hosts at
once, on top of concurrent.futures (the same pattern already proven in
harvest.py and spray.py), exposed as a reusable helper for other commands
(health, procs, netmap, scan, spray).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")


def hosts_from_file(path: str) -> list[str]:
    """Read a newline-separated host list, ignoring blanks and #-comments."""
    lines = Path(path).read_text().splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def run_over_hosts(hosts: list[str], fn: Callable[[str], T], parallel: int = 10) -> dict[str, T]:
    """
    Call fn(host) for every host in `hosts`, up to `parallel` at once.
    Returns {host: result}. If fn raises for a host, the exception object
    itself is stored as that host's result rather than aborting the run.
    """
    results: dict[str, T] = {}
    if not hosts:
        return results

    with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
        futures = {ex.submit(fn, h): h for h in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                results[host] = future.result()
            except Exception as e:  # noqa: BLE001 - surfaced to caller as data
                results[host] = e
    # Preserve input order rather than completion order.
    return {h: results[h] for h in hosts if h in results}
