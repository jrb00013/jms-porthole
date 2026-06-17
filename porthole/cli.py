import sys
import click
from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """[bold cyan]
 ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ ██████╗ ██╗     ███████╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗██║     ██╔════╝
 ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║   ██║██║     █████╗
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║   ██║██║     ██╔══╝
 ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║╚██████╔╝███████╗███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
[/bold cyan][dim]  remote monitoring & recon toolkit[/dim]
"""


def get_credentials(username, password):
    if not username:
        username = click.prompt("Username")
    if not password:
        password = click.prompt("Password", hide_input=True)
    return username, password


@click.group()
@click.version_option("0.1.0", prog_name="porthole")
def main():
    """porthole — remote monitoring & recon toolkit"""
    pass


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("--stop", is_flag=True, help="Stop the broadcast on remote host")
def broadcast(host, username, password, stop):
    """Start (or stop) a VNC desktop broadcast from HOST."""
    from .broadcast import start_broadcast, stop_broadcast, print_connection_info
    import time

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


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("-i", "--interval", default=3, show_default=True, help="Refresh interval in seconds")
def monitor(host, username, password, interval):
    """Live system monitor (CPU, RAM, disk, processes) on HOST."""
    from .monitor import run_monitor
    username, password = get_credentials(username, password)
    run_monitor(host, username, password, interval)


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
def sysinfo(host, username, password):
    """Dump full system info from HOST."""
    from .sysinfo import collect_sysinfo, print_sysinfo
    username, password = get_credentials(username, password)
    console.print(f"[cyan]Collecting system info from [bold]{host}[/bold]...[/cyan]")
    with __import__("porthole.ssh", fromlist=["SSHClient"]).SSHClient(host, username, password) as ssh:
        info = collect_sysinfo(ssh)
    print_sysinfo(host, info)


@main.command()
@click.argument("target", metavar="HOST_OR_CIDR")
@click.option("--ports", default=None, help="Comma-separated ports to scan (default: common ports)")
@click.option("--threads", default=100, show_default=True, help="Thread count")
def scan(target, ports, threads):
    """Scan a host or CIDR network for open ports / live hosts."""
    from .scanner import scan_ports, scan_network, print_scan_results, print_network_results, COMMON_PORTS

    if "/" in target:
        console.print(f"[cyan]Scanning network [bold]{target}[/bold]...[/cyan]")
        live = scan_network(target, threads)
        print_network_results(target, live)
    else:
        port_list = [int(p) for p in ports.split(",")] if ports else list(COMMON_PORTS.keys())
        console.print(f"[cyan]Scanning [bold]{target}[/bold] ({len(port_list)} ports)...[/cyan]")
        results = scan_ports(target, port_list, threads)
        print_scan_results(target, results)


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
def shell(host, username, password):
    """Open an interactive SSH shell on HOST."""
    from .shell import interactive_shell
    username, password = get_credentials(username, password)
    interactive_shell(host, username, password)


@main.command()
@click.argument("host")
@click.argument("local_port", type=int)
@click.argument("remote_port", type=int)
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("--remote-host", default="localhost", show_default=True, help="Remote host to forward to")
def tunnel(host, local_port, remote_port, username, password, remote_host):
    """Forward LOCAL_PORT through HOST to REMOTE_HOST:REMOTE_PORT."""
    from .tunnel import open_tunnel
    username, password = get_credentials(username, password)
    open_tunnel(host, username, password, local_port, remote_host, remote_port)


@main.command()
@click.argument("host")
@click.argument("filepath")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("-n", "--lines", default=50, show_default=True, help="Initial lines to show")
def watch(host, filepath, username, password, lines):
    """Tail -f FILEPATH on HOST with live colorized output."""
    from .watcher import watch_file
    username, password = get_credentials(username, password)
    watch_file(host, username, password, filepath, lines)


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("--service", default=None, help="Filter by systemd service name")
def logs(host, username, password, service):
    """Watch live journalctl logs on HOST."""
    from .watcher import watch_logs
    username, password = get_credentials(username, password)
    watch_logs(host, username, password, service)


@main.command()
@click.argument("host")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("-o", "--output", default=None, help="Output file path (default: ~/porthole_screenshot_*.png)")
def screenshot(host, username, password, output):
    """Capture a screenshot of HOST's desktop and download it."""
    from .screenshot import capture_screenshot
    username, password = get_credentials(username, password)
    capture_screenshot(host, username, password, output)


@main.command()
@click.argument("hosts", nargs=-1, required=True)
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
@click.option("-f", "--file", "hosts_file", default=None, help="File with one host per line")
@click.option("--threads", default=10, show_default=True, help="Parallel thread count")
def harvest(hosts, username, password, hosts_file, threads):
    """Gather system info from multiple hosts in parallel.

    Pass hosts as arguments or use -f with a file (one host per line).

    Examples:\n
      porthole harvest 10.0.0.1 10.0.0.2 -u admin\n
      porthole harvest -f hosts.txt -u admin
    """
    from .harvest import harvest as do_harvest, print_harvest_results

    username, password = get_credentials(username, password)

    host_list = list(hosts)
    if hosts_file:
        with open(hosts_file) as f:
            host_list += [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not host_list:
        console.print("[red]No hosts provided[/red]")
        sys.exit(1)

    results = do_harvest(host_list, username, password, threads)
    print_harvest_results(results)


@main.command()
@click.argument("hosts", nargs=-1, required=True)
@click.argument("command")
@click.option("-u", "--username", default=None, help="SSH username")
@click.option("-p", "--password", default=None, help="SSH password")
def exec(hosts, command, username, password):
    """Run COMMAND on multiple hosts in parallel and show results."""
    from .shell import run_command_on_hosts
    username, password = get_credentials(username, password)
    run_command_on_hosts(list(hosts), username, password, command)
