"""
Remote secret scanning — find exposed credentials, API keys, and private keys.
"""
import re
from rich.console import Console
from rich.table import Table
from .ssh import SSHClient

console = Console()

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"(?i)aws[_\s.-]*secret[_\s.-]*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "GitLab Token": r"glpat-[A-Za-z0-9\-]{20,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    "Password in Config": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Database URL": r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'\"]+",
}

DEFAULT_PATHS = ["/etc", "/home", "/opt", "/var/www", "/root", "/srv"]
MAX_FILE_SIZE = 1_048_576  # 1 MB


def _build_grep_cmd(paths: list[str], extensions: str = None) -> str:
    path_str = " ".join(paths)
    ext_filter = ""
    if extensions:
        exts = extensions.split(",")
        ext_filter = " ".join(f"-name '*.{e}' -o" for e in exts).rstrip(" -o")
        find_cmd = f"find {path_str} -type f \\( {ext_filter} \\) -size -{MAX_FILE_SIZE}c 2>/dev/null"
    else:
        find_cmd = f"find {path_str} -type f -size -{MAX_FILE_SIZE}c 2>/dev/null"
    return find_cmd


def scan_remote(host: str, username: str, password: str,
                paths: list[str] = None, extensions: str = None,
                max_files: int = 500) -> list[dict]:
    paths = paths or DEFAULT_PATHS
    findings = []

    with SSHClient(host, username, password) as ssh:
        find_cmd = _build_grep_cmd(paths, extensions)
        file_list = ssh.run_out(f"{find_cmd} | head -{max_files}")
        files = [f for f in file_list.splitlines() if f.strip()]

        for pattern_name, pattern in SECRET_PATTERNS.items():
            regex = re.compile(pattern)
            for filepath in files:
                content = ssh.run_out(f"cat '{filepath}' 2>/dev/null", timeout=10)
                if not content:
                    continue
                for i, line in enumerate(content.splitlines(), 1):
                    if regex.search(line):
                        findings.append({
                            "file": filepath,
                            "line": i,
                            "type": pattern_name,
                            "snippet": line.strip()[:120],
                        })

    return findings


def print_secret_results(host: str, findings: list[dict]):
    if not findings:
        console.print(f"[green]No secrets found on {host}.[/green]")
        return

    table = Table(title=f"Secret Scan — {host} ({len(findings)} findings)", border_style="red")
    table.add_column("Type", style="bold red")
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right")
    table.add_column("Snippet", style="dim", max_width=60)

    for f in findings:
        table.add_row(f["type"], f["file"], str(f["line"]), f["snippet"])

    console.print(table)
