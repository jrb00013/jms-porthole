# JMS Porthole

**Janus Monitoring Suite** — a Python CLI toolkit for remote monitoring, desktop broadcasting, and network recon.

```
     JMS    PORTHOLE
     ───    ────────
     Janus Monitoring Suite
```

Installable as a Python package. All commands available as `jms <command>` or `porthole <command>`.

---

## Install

```bash
./install.sh
```

Or manually:

```bash
pip install .
```

---

## Commands

| Command | Description |
|---|---|
| `jms broadcast HOST` | Stream HOST desktop over VNC |
| `jms monitor HOST` | Live CPU / RAM / disk / process monitor |
| `jms sysinfo HOST` | Full system info dump |
| `jms scan HOST_OR_CIDR` | Port scan or network sweep |
| `jms probe HOST` | Deep service fingerprinting with banner grab |
| `jms shell HOST` | Interactive SSH shell |
| `jms screenshot HOST` | Capture and download a desktop screenshot |
| `jms watch HOST FILE` | Tail a file with live colorized output |
| `jms logs HOST` | Watch journalctl live |
| `jms tunnel HOST LOCAL REMOTE` | SSH port forward |
| `jms harvest HOST...` | Multi-host info gathering in parallel |
| `jms exec -c CMD HOST...` | Run a command across multiple hosts |
| `jms upload HOST LOCAL REMOTE` | Upload a file via SFTP |
| `jms download HOST REMOTE LOCAL` | Download a file via SFTP |
| `jms ls HOST PATH` | List remote directory |
| `jms spray HOST...` | SSH credential spray (authorized testing) |
| `jms knock HOST PORTS...` | Send port knock sequence |
| `jms netmap CIDR` | Network map with reverse DNS |
| `jms traceroute HOST` | Traceroute to host |
| `jms hosts add/list/remove` | Manage saved host aliases |

---

## Examples

```bash
# Broadcast desktop (auto-detects display, installs x11vnc)
jms broadcast 192.168.30.73 -u heimdall

# Scan a subnet for live hosts
jms scan 192.168.30.0/24

# Scan with a preset (web, db, remote, devops, all)
jms scan 192.168.30.13 --preset db

# Deep service probe
jms probe 192.168.30.13

# Live monitor, 2s refresh
jms monitor 192.168.30.13 -u amer -i 2

# Harvest info from multiple hosts at once
jms harvest 192.168.30.1 192.168.30.13 192.168.30.73 -u admin

# Run a command on multiple hosts
jms exec -c "df -h" 192.168.30.1 192.168.30.2

# SSH tunnel — forward local 5432 to remote postgres
jms tunnel 192.168.30.13 5432 5432 -u amer

# Watch a log file live
jms watch 192.168.30.13 /var/log/syslog -u amer

# Screenshot
jms screenshot 192.168.30.73 -u heimdall

# Credential spray (authorized use only)
jms spray 192.168.30.0/24 -u admin,root -p admin,password

# Port knocking
jms knock 192.168.30.13 7000 8000 9000

# Save a host alias
jms hosts add heimdall 192.168.30.73 -u heimdall -p ubuntu
jms broadcast heimdall
```

---

## Output / Reporting

Most commands support `-o FILE` to save results as JSON:

```bash
jms scan 192.168.30.0/24 -o results.json
jms harvest 192.168.30.1 192.168.30.13 -u admin -o hosts.json
jms sysinfo 192.168.30.13 -u amer -o sysinfo.json
```

---

## Requirements

- Python 3.9+
- `sshpass` (installed automatically by `install.sh`)

Python dependencies (installed automatically):

- `paramiko` — SSH
- `rich` — terminal output
- `click` — CLI
- `scp` — file transfer

---

## License

MIT
