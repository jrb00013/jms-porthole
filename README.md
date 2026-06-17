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
| `jms health HOST CHECKS...` | HTTP/TCP health checks with latency |
| `jms diff HOST PATH [PATH2]` | Compare local vs remote or two remote files |
| `jms secrets HOST` | Scan for exposed API keys and credentials |
| `jms vuln HOST` | Security posture checks (SSH, packages, SUID) |
| `jms cert HOST` | TLS certificate expiry check |
| `jms keydeploy HOST` | Deploy SSH public key to authorized_keys |
| `jms backup HOST PATH` | Tarball and download a remote directory |
| `jms procs services/ps/restart/kill` | Remote service and process management |
| `jms dns lookup/enum/reverse` | DNS record lookup and subdomain enum |
| `jms alert HOST CHECKS...` | Health monitoring with webhook alerts |
| `jms logsearch HOST PATTERN` | Search remote journal and log files |
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

# Health check + cert expiry
jms health 192.168.30.13 tcp:22 https:443/
jms cert example.com --ports 443,8443

# Security scanning
jms secrets 192.168.30.13 -u admin --paths /etc,/home
jms vuln 192.168.30.13 -u admin

# Deploy SSH key and backup remote config
jms keydeploy 192.168.30.13 --key ~/.ssh/id_ed25519.pub
jms backup 192.168.30.13 /etc/nginx -o nginx-backup.tar.gz

# DNS enum and log search
jms dns enum example.com
jms logsearch 192.168.30.13 "error" --since "2 hours ago"

# Alert on service failure
jms alert 192.168.30.13 tcp:80 http:443/ --webhook https://hooks.example.com/alerts --interval 30
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
