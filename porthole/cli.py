import sys
import click
from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """[bold cyan]
     ██╗███╗   ███╗███████╗    ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ ██████╗ ██╗     ███████╗
     ██║████╗ ████║██╔════╝    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗██║     ██╔════╝
     ██║██╔████╔██║███████╗    ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║   ██║██║     █████╗
██   ██║██║╚██╔╝██║╚════██║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║   ██║██║     ██╔══╝
╚█████╔╝██║ ╚═╝ ██║███████║    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║╚██████╔╝███████╗███████╗
 ╚════╝ ╚═╝     ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
[/bold cyan][dim]  Janus Monitoring Suite — remote monitoring, broadcasting & recon[/dim]
"""


def get_credentials(username, password):
    if not username:
        username = click.prompt("Username")
    if not password:
        password = click.prompt("Password", hide_input=True)
    return username, password


def resolve_host(alias_or_host: str, username, password):
    """Resolve alias from config, fall back to raw host + prompted creds."""
    from .config import resolve
    resolved = resolve(alias_or_host)
    if resolved:
        host, u, p, _ = resolved
        return host, u or username, p or password
    return alias_or_host, username, password


@click.group()
@click.version_option("0.1.0", prog_name="jms")
def main():
    """JMS Porthole — Janus Monitoring Suite. Remote monitoring, broadcasting & recon toolkit."""
    pass


# ── BROADCAST ────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--stop", is_flag=True, help="Stop the broadcast on remote host")
def broadcast(host, username, password, stop):
    """Start (or stop) a VNC desktop broadcast from HOST."""
    from .broadcast import start_broadcast, stop_broadcast, print_connection_info
    import time

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    if stop:
        stop_broadcast(host, username, password)
        return

    console.print(BANNER)
    console.print(f"[cyan]Broadcasting desktop from [bold]{host}[/bold]...[/cyan]\n")

    try:
        info = start_broadcast(host, username, password)
        print_connection_info(info)
        console.print("[dim]Press Ctrl+C to exit (broadcast continues on remote)[/dim]\n")
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Exited. Broadcast still running on remote.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ── MONITOR ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-i", "--interval", default=3, show_default=True)
def monitor(host, username, password, interval):
    """Live system monitor (CPU, RAM, disk, processes) on HOST."""
    from .monitor import run_monitor
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    run_monitor(host, username, password, interval)


# ── SYSINFO ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-o", "--output", default=None, help="Save as JSON to this path")
def sysinfo(host, username, password, output):
    """Dump full system info from HOST."""
    from .sysinfo import collect_sysinfo, print_sysinfo
    from .report import to_json
    from .ssh import SSHClient

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    console.print(f"[cyan]Collecting system info from [bold]{host}[/bold]...[/cyan]")
    with SSHClient(host, username, password) as ssh:
        info = collect_sysinfo(ssh)

    print_sysinfo(host, info)

    if output:
        to_json(info, output)


# ── SCAN ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target", metavar="HOST_OR_CIDR")
@click.option("--ports", default=None, help="Comma-separated ports (default: common)")
@click.option("--preset", default=None, type=click.Choice(["web", "db", "remote", "devops", "all"]),
              help="Port preset shortcut")
@click.option("--threads", default=100, show_default=True)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def scan(target, ports, preset, threads, output):
    """Scan a host or CIDR network for open ports / live hosts.

    Port presets: --preset web|db|remote|devops|all
    """
    from .scanner import scan_ports, scan_network, print_scan_results, print_network_results, COMMON_PORTS
    from .scan_cli_extras import resolve_port_preset
    from .report import to_json

    if "/" in target:
        console.print(f"[cyan]Scanning network [bold]{target}[/bold]...[/cyan]")
        live = scan_network(target, threads)
        print_network_results(target, live)
        if output:
            to_json(live, output)
    else:
        if preset:
            port_list = resolve_port_preset(preset)
        elif ports:
            port_list = [int(p) for p in ports.split(",")]
        else:
            port_list = list(COMMON_PORTS.keys())
        console.print(f"[cyan]Scanning [bold]{target}[/bold] ({len(port_list)} ports)...[/cyan]")
        results = scan_ports(target, port_list, threads)
        print_scan_results(target, results)
        if output:
            to_json([{"port": k, "info": v} for k, v in results.items()], output)


# ── PROBE ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("--ports", default=None, help="Comma-separated ports to probe")
@click.option("-o", "--output", default=None, help="Save results as JSON")
def probe(host, ports, output):
    """Deep service fingerprinting — banner grab, TLS info, version detection."""
    from .probe import probe_host, print_probe_results
    from .report import to_json

    port_list = [int(p) for p in ports.split(",")] if ports else None
    console.print(f"[cyan]Probing services on [bold]{host}[/bold]...[/cyan]")
    results = probe_host(host, port_list)
    print_probe_results(host, results)
    if output:
        to_json(results, output)


# ── SHELL ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
def shell(host, username, password):
    """Open an interactive SSH shell on HOST."""
    from .shell import interactive_shell
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    interactive_shell(host, username, password)


# ── TUNNEL ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("local_port", type=int)
@click.argument("remote_port", type=int)
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--remote-host", default="localhost", show_default=True)
def tunnel(host, local_port, remote_port, username, password, remote_host):
    """Forward LOCAL_PORT through HOST to REMOTE_HOST:REMOTE_PORT."""
    from .tunnel import open_tunnel
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    open_tunnel(host, username, password, local_port, remote_host, remote_port)


# ── WATCH / LOGS ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("filepath")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-n", "--lines", default=50, show_default=True)
def watch(host, filepath, username, password, lines):
    """Tail -f FILEPATH on HOST with live colorized output."""
    from .watcher import watch_file
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    watch_file(host, username, password, filepath, lines)


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--service", default=None, help="Filter by systemd service name")
def logs(host, username, password, service):
    """Watch live journalctl logs on HOST."""
    from .watcher import watch_logs
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    watch_logs(host, username, password, service)


# ── SCREENSHOT ────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-o", "--output", default=None)
def screenshot(host, username, password, output):
    """Capture a screenshot of HOST's desktop and download it."""
    from .screenshot import capture_screenshot
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    capture_screenshot(host, username, password, output)


# ── HARVEST ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("hosts", nargs=-1)
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-f", "--file", "hosts_file", default=None, help="File with one host per line")
@click.option("--threads", default=10, show_default=True)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def harvest(hosts, username, password, hosts_file, threads, output):
    """Gather system info from multiple hosts in parallel."""
    from .harvest import harvest as do_harvest, print_harvest_results
    from .report import to_json

    username, password = get_credentials(username, password)
    host_list = list(hosts)
    if hosts_file:
        with open(hosts_file) as f:
            host_list += [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not host_list:
        console.print("[red]No hosts provided.[/red]")
        sys.exit(1)

    results = do_harvest(host_list, username, password, threads)
    print_harvest_results(results)
    if output:
        to_json(results, output)


# ── EXEC ──────────────────────────────────────────────────────────────────────

@main.command(name="exec")
@click.argument("hosts", nargs=-1, required=True)
@click.option("-c", "--command", required=True, help="Command to run")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def exec_cmd(hosts, command, username, password, output):
    """Run COMMAND on multiple hosts in parallel. Use -c 'cmd'."""
    from .shell import run_command_on_hosts
    from .report import to_json
    username, password = get_credentials(username, password)
    run_command_on_hosts(list(hosts), username, password, command)


# ── TRANSFER ──────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("local_path")
@click.argument("remote_path")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
def upload(host, local_path, remote_path, username, password):
    """Upload LOCAL_PATH to HOST:REMOTE_PATH via SFTP."""
    from .transfer import upload_file
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    upload_file(host, username, password, local_path, remote_path)


@main.command()
@click.argument("host")
@click.argument("remote_path")
@click.argument("local_path")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
def download(host, remote_path, local_path, username, password):
    """Download HOST:REMOTE_PATH to LOCAL_PATH via SFTP."""
    from .transfer import download_file
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    download_file(host, username, password, remote_path, local_path)


@main.command(name="ls")
@click.argument("host")
@click.argument("path", default=".")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
def ls_remote(host, path, username, password):
    """List files on HOST:PATH via SFTP."""
    from .transfer import list_remote_dir
    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    list_remote_dir(host, username, password, path)


# ── SPRAY ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("hosts", nargs=-1, required=True)
@click.option("-u", "--usernames", required=True, help="Comma-separated usernames")
@click.option("-p", "--passwords", required=True, help="Comma-separated passwords")
@click.option("--port", default=22, show_default=True)
@click.option("--threads", default=10, show_default=True)
@click.option("-o", "--output", default=None, help="Save hits as JSON")
def spray(hosts, usernames, passwords, port, threads, output):
    """SSH credential spray across hosts. For authorized testing only."""
    from .spray import spray_hosts, print_spray_results
    from .report import to_json

    u_list = [u.strip() for u in usernames.split(",")]
    p_list = [p.strip() for p in passwords.split(",")]

    console.print(f"[yellow]⚠ For authorized use only[/yellow]")
    results = spray_hosts(list(hosts), u_list, p_list, port, threads)
    print_spray_results(results)
    if output:
        to_json([r for r in results if r["success"]], output)


# ── KNOCK ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("ports", nargs=-1, required=True, type=int)
@click.option("--proto", type=click.Choice(["tcp", "udp"]), default="tcp", show_default=True)
@click.option("--delay", default=0.1, show_default=True, help="Delay between knocks (seconds)")
def knock(host, ports, proto, delay):
    """Send a port knock sequence to HOST."""
    from .portknock import knock as do_knock
    do_knock(host, list(ports), proto, delay)


# ── NETMAP ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("cidr")
@click.option("--no-dns", is_flag=True, help="Skip reverse DNS lookups")
@click.option("--threads", default=50, show_default=True)
@click.option("-o", "--output", default=None)
def netmap(cidr, no_dns, threads, output):
    """Network map — ICMP/TCP ping sweep with reverse DNS."""
    from .netmap import map_network, print_map_results
    from .report import to_json

    console.print(f"[cyan]Mapping [bold]{cidr}[/bold]...[/cyan]")
    results = map_network(cidr, resolve_dns=not no_dns, threads=threads)
    print_map_results(cidr, results)
    if output:
        to_json(results, output)


@main.command()
@click.argument("host")
@click.option("--max-hops", default=20, show_default=True)
def traceroute(host, max_hops):
    """Traceroute to HOST showing each hop."""
    from .netmap import traceroute as do_trace, print_traceroute
    console.print(f"[cyan]Tracing route to [bold]{host}[/bold]...[/cyan]")
    hops = do_trace(host, max_hops)
    print_traceroute(host, hops)


# ── HOST ALIAS MANAGEMENT ─────────────────────────────────────────────────────

@main.group()
def hosts():
    """Manage saved host aliases."""
    pass


@hosts.command(name="add")
@click.argument("alias")
@click.argument("host")
@click.option("-u", "--username", required=True)
@click.option("-p", "--password", default="")
@click.option("--port", default=22, show_default=True)
def hosts_add(alias, host, username, password, port):
    """Save a host alias: jms hosts add prod 192.168.1.10 -u admin"""
    from .config import save_host
    save_host(alias, host, username, password, port)


@hosts.command(name="list")
def hosts_list():
    """List saved host aliases."""
    from .config import list_hosts
    list_hosts()


@hosts.command(name="remove")
@click.argument("alias")
def hosts_remove(alias):
    """Remove a saved host alias."""
    from .config import delete_host
    delete_host(alias)
# ── HEALTH ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("checks", nargs=-1, required=True)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def health(host, checks, output):
    """Run HTTP/TCP health checks on HOST.

    Check specs: tcp:22  http:80/  https:443/api
    """
    from .health import run_health_checks, print_health_results
    from .health import parse_check_specs
    from .report import to_json

    check_list = parse_check_specs(checks)
    if not check_list:
        console.print("[red]No valid checks specified. Use tcp:PORT or http:PORT/path[/red]")
        sys.exit(1)

    console.print(f"[cyan]Running {len(check_list)} health check(s) on [bold]{host}[/bold]...[/cyan]")
    results = run_health_checks(host, check_list)
    print_health_results(host, results)
    if output:
        to_json(results, output)


# ── DIFF ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("path_a")
@click.argument("path_b", required=False)
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--local", "local_path", default=None, help="Compare LOCAL file against remote PATH_A")
def diff(host, path_a, path_b, username, password, local_path):
    """Compare files on HOST or local vs remote.

    Remote vs remote: jms diff HOST /etc/a.conf /etc/b.conf
    Local vs remote:  jms diff HOST /etc/app.conf --local ./app.conf
    """
    from .diff import diff_local_remote, diff_remote_remote

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    if local_path:
        diff_local_remote(host, username, password, local_path, path_a)
    elif path_b:
        diff_remote_remote(host, username, password, path_a, path_b)
    else:
        console.print("[red]Provide PATH_B or --local LOCAL_PATH[/red]")
        sys.exit(1)

# ── SECRETS ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--paths", default=None, help="Comma-separated paths to scan")
@click.option("--ext", default=None, help="File extensions filter (e.g. conf,env,yml)")
@click.option("-o", "--output", default=None, help="Save findings as JSON")
def secrets(host, username, password, paths, ext, output):
    """Scan HOST for exposed secrets, API keys, and credentials."""
    from .secrets import scan_remote, print_secret_results
    from .report import to_json

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    path_list = [p.strip() for p in paths.split(",")] if paths else None
    console.print(f"[cyan]Scanning [bold]{host}[/bold] for secrets...[/cyan]")
    findings = scan_remote(host, username, password, paths=path_list, extensions=ext)
    print_secret_results(host, findings)
    if output:
        to_json(findings, output)

# ── VULN ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def vuln(host, username, password, output):
    """Run security posture checks on HOST."""
    from .vuln import run_vuln_checks, print_vuln_results
    from .report import to_json

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    console.print(f"[cyan]Running security checks on [bold]{host}[/bold]...[/cyan]")
    results = run_vuln_checks(host, username, password)
    print_vuln_results(host, results)
    if output:
        to_json(results, output)

# ── CERT ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.option("--ports", default="443", show_default=True, help="Comma-separated ports")
@click.option("-o", "--output", default=None, help="Save results as JSON")
def cert(host, ports, output):
    """Check TLS certificate expiry on HOST."""
    from .cert import check_certs, print_cert_results
    from .report import to_json

    port_list = [int(p) for p in ports.split(",")]
    console.print(f"[cyan]Checking certificates on [bold]{host}[/bold]...[/cyan]")
    results = check_certs(host, port_list)
    print_cert_results(host, results)
    if output:
        to_json(results, output)

# ── KEYDEPLOY ─────────────────────────────────────────────────────────────────

@main.command(name="keydeploy")
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--key", "key_path", default="~/.ssh/id_rsa.pub", show_default=True)
@click.option("--comment", default=None, help="Comment tag for the deployed key")
@click.option("--list", "list_keys", is_flag=True, help="List remote authorized keys")
def keydeploy(host, username, password, key_path, comment, list_keys):
    """Deploy an SSH public key to HOST authorized_keys."""
    from .keydeploy import deploy_key, list_remote_keys, print_remote_keys

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    if list_keys:
        keys = list_remote_keys(host, username, password)
        print_remote_keys(host, keys)
        return

    deploy_key(host, username, password, key_path, comment)

# ── BACKUP ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("remote_path")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("-o", "--output", default=None, help="Local output path (.tar.gz)")
@click.option("--exclude", default=None, help="Comma-separated paths to exclude")
def backup(host, remote_path, username, password, output, exclude):
    """Backup a remote directory as a compressed tarball."""
    from .backup import backup_remote

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    exclude_list = [e.strip() for e in exclude.split(",")] if exclude else None
    backup_remote(host, username, password, remote_path, output, exclude_list)

# ── PROCS ─────────────────────────────────────────────────────────────────────

@main.group()
def procs():
    """Remote process and service management."""
    pass


@procs.command(name="services")
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--state", default=None, help="Filter by state (active, failed, inactive)")
def procs_services(host, username, password, state):
    """List systemd services on HOST."""
    from .procs import list_services, print_services

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    services = list_services(host, username, password, filter_state=state)
    print_services(host, services)


@procs.command(name="ps")
@click.argument("host")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--sort", "sort_by", default="cpu", type=click.Choice(["cpu", "mem", "pid"]))
@click.option("-n", "--limit", default=20, show_default=True)
def procs_ps(host, username, password, sort_by, limit):
    """List top processes on HOST."""
    from .procs import list_processes, print_processes

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    procs = list_processes(host, username, password, sort_by=sort_by, limit=limit)
    print_processes(host, procs)


@procs.command(name="restart")
@click.argument("host")
@click.argument("service")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
def procs_restart(host, service, username, password):
    """Restart a systemd service on HOST."""
    from .procs import service_action

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    ok, msg = service_action(host, username, password, service, "restart")
    if ok:
        console.print(f"[green]Restarted {service} on {host}[/green]")
    else:
        console.print(f"[red]Failed to restart {service}:[/red] {msg}")
        sys.exit(1)


@procs.command(name="kill")
@click.argument("host")
@click.argument("pid", type=int)
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--signal", default="TERM", show_default=True)
def procs_kill(host, pid, username, password, signal):
    """Send a signal to PID on HOST."""
    from .procs import kill_process

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)
    ok, msg = kill_process(host, username, password, pid, signal)
    if ok:
        console.print(f"[green]Sent {signal} to PID {pid} on {host}[/green]")
    else:
        console.print(f"[red]Failed:[/red] {msg}")
        sys.exit(1)

# ── DNS ───────────────────────────────────────────────────────────────────────

@main.group()
def dns():
    """DNS enumeration and record lookup."""
    pass


@dns.command(name="lookup")
@click.argument("domain")
@click.option("--type", "rtype", default=None, help="Record type (A,MX,TXT,NS,...) or omit for all")
@click.option("-o", "--output", default=None, help="Save results as JSON")
def dns_lookup(domain, rtype, output):
    """Look up DNS records for DOMAIN."""
    from .dns import lookup_records, print_dns_results
    from .report import to_json

    rtypes = [rtype.upper()] if rtype else None
    records = lookup_records(domain, rtypes)
    print_dns_results(domain, records)
    if output:
        to_json(records, output)


@dns.command(name="enum")
@click.argument("domain")
@click.option("-o", "--output", default=None, help="Save results as JSON")
def dns_enum(domain, output):
    """Enumerate common subdomains for DOMAIN."""
    from .dns import enumerate_subdomains, print_subdomain_results
    from .report import to_json

    console.print(f"[cyan]Enumerating subdomains for [bold]{domain}[/bold]...[/cyan]")
    found = enumerate_subdomains(domain)
    print_subdomain_results(domain, found)
    if output:
        to_json(found, output)


@dns.command(name="reverse")
@click.argument("ip")
def dns_reverse(ip):
    """Reverse DNS lookup for IP."""
    from .dns import reverse_dns

    hostname = reverse_dns(ip)
    if hostname:
        console.print(f"[green]{ip}[/green] → [bold]{hostname}[/bold]")
    else:
        console.print(f"[dim]No PTR record for {ip}[/dim]")

# ── ALERT ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("host")
@click.argument("checks", nargs=-1, required=True)
@click.option("--interval", default=60, show_default=True, help="Check interval in seconds")
@click.option("--webhook", default=None, help="Webhook URL for failure alerts")
@click.option("--slack", is_flag=True, help="Send Slack-formatted webhook payload")
@click.option("--once", is_flag=True, help="Run once and exit (no loop)")
def alert(host, checks, interval, webhook, slack, once):
    """Monitor HOST health checks and alert on failure.

    Check specs: tcp:22  http:80/  https:443/api
    """
    from .alert import run_alert_loop
    from .health import parse_check_specs

    check_list = parse_check_specs(checks)
    if not check_list:
        console.print("[red]No valid checks specified.[/red]")
        sys.exit(1)

    max_iter = 1 if once else None
    run_alert_loop(host, check_list, interval=interval, webhook=webhook,
                   slack=slack, max_iterations=max_iter)


# ── LOGSEARCH ─────────────────────────────────────────────────────────────────

@main.command(name="logsearch")
@click.argument("host")
@click.argument("pattern")
@click.option("-u", "--username", default=None)
@click.option("-p", "--password", default=None)
@click.option("--since", default="1 hour ago", show_default=True, help="Journal time window")
@click.option("--paths", default=None, help="Comma-separated log directories")
@click.option("--journal-only", is_flag=True, help="Search journalctl only")
@click.option("--files-only", is_flag=True, help="Search log files only")
@click.option("-n", "--limit", default=100, show_default=True)
@click.option("-o", "--output", default=None, help="Save results as JSON")
def logsearch(host, pattern, username, password, since, paths, journal_only, files_only, limit, output):
    """Search remote logs on HOST for PATTERN."""
    from .logsearch import search_journal, search_files, search_all, print_search_results
    from .report import to_json

    host, username, password = resolve_host(host, username, password)
    username, password = get_credentials(username, password)

    path_list = [p.strip() for p in paths.split(",")] if paths else None

    if journal_only:
        results = search_journal(host, username, password, pattern, since=since, limit=limit)
    elif files_only:
        results = search_files(host, username, password, pattern, paths=path_list, limit=limit)
    else:
        results = search_all(host, username, password, pattern, since=since, paths=path_list, limit=limit)

    print_search_results(host, pattern, results)
    if output:
        to_json(results, output)
