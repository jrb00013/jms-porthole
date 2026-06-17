# porthole

Remote monitoring, broadcasting, and recon toolkit — installable Python CLI.

## Install

```bash
./install.sh
```

Or manually:

```bash
pip install .
```

## Commands

| Command | Description |
|---|---|
| `porthole broadcast HOST` | Stream HOST's desktop over VNC |
| `porthole monitor HOST` | Live CPU / RAM / disk / process monitor |
| `porthole sysinfo HOST` | Full system info dump |
| `porthole scan HOST_OR_CIDR` | Port scan or network sweep |
| `porthole shell HOST` | Interactive SSH shell |
| `porthole screenshot HOST` | Capture and download a desktop screenshot |
| `porthole watch HOST FILE` | Tail a file with live colorized output |
| `porthole logs HOST` | Watch journalctl live |
| `porthole tunnel HOST LOCAL REMOTE` | SSH port forward |
| `porthole harvest HOST [HOST...]` | Multi-host info gathering in parallel |
| `porthole exec HOST [HOST...] CMD` | Run a command across multiple hosts |

## Examples

```bash
# Broadcast a desktop
porthole broadcast 192.168.30.73 -u heimdall

# Scan a whole subnet
porthole scan 192.168.30.0/24

# Scan specific ports on a host
porthole scan 192.168.30.13 --ports 22,80,443,3306,5432

# Live monitor
porthole monitor 192.168.30.13 -u amer -i 2

# Gather info from multiple hosts at once
porthole harvest 192.168.30.1 192.168.30.13 192.168.30.73 -u admin

# Run a command on multiple hosts
porthole exec 192.168.30.1 192.168.30.2 "df -h"

# SSH tunnel: forward local 5432 to remote postgres
porthole tunnel 192.168.30.13 5432 5432 -u amer

# Watch a log file
porthole watch 192.168.30.13 /var/log/syslog -u amer

# Take a screenshot
porthole screenshot 192.168.30.73 -u heimdall
```

## Requirements

- Python 3.9+
- `sshpass` (installed automatically by `install.sh`)
