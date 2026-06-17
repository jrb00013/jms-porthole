import os
import tempfile
import time
from datetime import datetime
from rich.console import Console
from .ssh import SSHClient

console = Console()


def capture_screenshot(host: str, username: str, password: str, output_path: str = None) -> str:
    """
    Capture a screenshot of the remote X display using scrot or import.
    Downloads the file locally and returns the local path.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.expanduser(f"~/porthole_screenshot_{host}_{timestamp}.png")

    remote_tmp = f"/tmp/porthole_shot_{int(time.time())}.png"

    with SSHClient(host, username, password) as ssh:
        # Detect display
        display_socket = ssh.run_out("ls /tmp/.X11-unix/ | head -1")
        display = ":" + display_socket.lstrip("X") if display_socket else ":0"

        xauth = ssh.run_out("ls /run/user/*/gdm/Xauthority 2>/dev/null | head -1 || echo $HOME/.Xauthority")

        # Try scrot first, then import (ImageMagick), then xwd
        tools = [
            f"DISPLAY={display} XAUTHORITY={xauth} scrot {remote_tmp}",
            f"DISPLAY={display} XAUTHORITY={xauth} import -window root {remote_tmp}",
            f"DISPLAY={display} XAUTHORITY={xauth} xwd -root -silent | convert xwd:- {remote_tmp}",
        ]

        captured = False
        for tool_cmd in tools:
            tool_name = tool_cmd.split()[2] if "DISPLAY" in tool_cmd else tool_cmd.split()[0]
            _, _, code = ssh.run(tool_cmd)
            if code == 0:
                captured = True
                break
            # Try to install if missing
            pkg = tool_name.split("/")[-1]
            if pkg == "import":
                pkg = "imagemagick"
            console.print(f"[yellow]{tool_name} not found, trying to install {pkg}...[/yellow]")
            ssh.run_sudo(f"apt-get install -y {pkg} -qq")
            _, _, code = ssh.run(tool_cmd)
            if code == 0:
                captured = True
                break

        if not captured:
            raise RuntimeError("Could not capture screenshot — no suitable tool available")

        # Download via SFTP
        console.print(f"[cyan]Downloading screenshot...[/cyan]")
        sftp = ssh.get_sftp()
        sftp.get(remote_tmp, output_path)
        sftp.remove(remote_tmp)
        sftp.close()

    console.print(f"[green]Screenshot saved to: {output_path}[/green]")
    return output_path
