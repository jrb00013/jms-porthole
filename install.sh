#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ ██████╗ ██╗     ███████╗"
echo "  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗██║     ██╔════╝"
echo "  ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║   ██║██║     █████╗  "
echo "  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║   ██║██║     ██╔══╝  "
echo "  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║╚██████╔╝███████╗███████╗"
echo "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝"
echo "  installer"
echo ""

# Check python3
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "Installing pip..."
    sudo apt-get install -y python3-pip
fi

# Install sshpass (needed for legacy broadcast script)
if ! command -v sshpass &> /dev/null; then
    echo "Installing sshpass..."
    sudo apt-get install -y sshpass 2>/dev/null || brew install hudochenkov/sshpass/sshpass 2>/dev/null || true
fi

echo "Installing porthole..."
pip3 install --quiet "$SCRIPT_DIR"

# Verify
if command -v porthole &> /dev/null; then
    echo ""
    echo "  porthole installed successfully!"
    echo ""
    echo "  Usage:"
    echo "    porthole --help"
    echo "    porthole broadcast 192.168.1.100 -u user"
    echo "    porthole scan 192.168.1.0/24"
    echo "    porthole monitor 192.168.1.100 -u user"
    echo "    porthole sysinfo 192.168.1.100 -u user"
    echo "    porthole harvest 10.0.0.1 10.0.0.2 -u admin"
    echo "    porthole shell 192.168.1.100 -u user"
    echo "    porthole screenshot 192.168.1.100 -u user"
    echo "    porthole watch 192.168.1.100 /var/log/syslog -u user"
    echo "    porthole tunnel 192.168.1.100 8080 80 -u user"
    echo ""
else
    echo ""
    echo "  Installed but 'porthole' not in PATH."
    echo "  Try: export PATH=\$PATH:\$(python3 -m site --user-base)/bin"
    echo ""
fi
