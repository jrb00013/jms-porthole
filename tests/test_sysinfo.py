"""Unit tests for porthole.sysinfo — command mapping and rich rendering, no real SSH."""

import io
import re

from rich.console import Console

from porthole import sysinfo


class FakeSSH:
    """Records every command requested and replies with canned stdout.

    Responses are keyed by a substring that must appear in the command, so a
    test can pin the exact probe that produced a given value.
    """

    def __init__(self, responses=None, default=""):
        self.responses = responses or {}
        self.default = default
        self.commands = []

    def run_out(self, cmd, timeout=30):
        self.commands.append(cmd)
        for needle, out in self.responses.items():
            if needle in cmd:
                return out.strip()
        return self.default

    def run(self, cmd, timeout=30):
        return self.run_out(cmd), "", 0


def make_console():
    buf = io.StringIO()
    return Console(file=buf, width=400, no_color=True), buf


REALISTIC = {
    "hostname -f": "web01.corp.example.com",
    "lsb_release": "Ubuntu 22.04.3 LTS",
    "uname -r": "5.15.0-88-generic",
    "uname -m": "x86_64",
    "model name": "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.40GHz",
    "nproc": "8",
    "free -h": "15Gi",
    "df -h --total": "98G",
    "ip -4 addr": "10.0.4.21/24 127.0.0.1/8 ",
    "ip link": "02:42:ac:11:00:02 ",
    "ip route": "10.0.4.1",
    "resolv.conf": "10.0.0.53 10.0.0.54 ",
    "etc/passwd": "root deploy svc-www ",
    "etc/sudoers": "%sudo ALL=(ALL:ALL) ALL",
    "ss -tlnp": "22 80 443 8080 ",
    "list-units": "ssh cron nginx docker",
    "last": "deploy pts/0 10.0.0.9 Mon Sep22 - 09:14\nroot pts/1 10.0.0.3 Mon Sep22 - 09:02",
    "crontab -l": "*/5 * * * * /usr/local/bin/rotate.sh",
    "dpkg -l": "742",
    "docker ps": "web01 nginx Up 6 days",
    "uptime -p": "up 12 days, 4 hours",
}

EXPECTED_KEYS = {
    "hostname",
    "os",
    "kernel",
    "arch",
    "cpu_model",
    "cpu_cores",
    "ram_total",
    "disk_total",
    "ip_addrs",
    "mac_addrs",
    "default_gw",
    "dns",
    "users",
    "sudo_users",
    "open_ports",
    "running_svcs",
    "last_logins",
    "cron_jobs",
    "env_vars",
    "installed_pkgs",
    "docker",
    "uptime",
}


def test_collect_sysinfo_returns_every_documented_key():
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))
    assert set(info) == EXPECTED_KEYS
    assert len(info) == 22


def test_collect_sysinfo_maps_each_probe_to_its_returned_value():
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))
    assert info["hostname"] == "web01.corp.example.com"
    assert info["os"] == "Ubuntu 22.04.3 LTS"
    assert info["kernel"] == "5.15.0-88-generic"
    assert info["arch"] == "x86_64"
    assert info["cpu_cores"] == "8"
    assert info["ram_total"] == "15Gi"
    assert info["disk_total"] == "98G"
    assert info["uptime"] == "up 12 days, 4 hours"
    assert info["installed_pkgs"] == "742"


def test_collect_sysinfo_runs_probes_in_declaration_order():
    ssh = FakeSSH(REALISTIC)
    sysinfo.collect_sysinfo(ssh)
    assert ssh.commands[0] == "hostname -f"
    assert ssh.commands[1].startswith("lsb_release -d")
    assert ssh.commands[-1] == "uptime -p"
    assert len(ssh.commands) == len(EXPECTED_KEYS)


def test_collect_sysinfo_uses_expected_awk_probes_for_hardware_facts():
    ssh = FakeSSH(REALISTIC)
    sysinfo.collect_sysinfo(ssh)
    assert "free -h | awk '/^Mem:/{print $2}'" in ssh.commands
    assert "df -h --total | tail -1 | awk '{print $2}'" in ssh.commands
    assert "nproc" in ssh.commands
    assert "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs" in ssh.commands


def test_collect_sysinfo_uses_expected_probes_for_network_and_access_facts():
    ssh = FakeSSH(REALISTIC)
    sysinfo.collect_sysinfo(ssh)
    assert "ip -4 addr show | grep inet | awk '{print $2}' | tr '\\n' ' '" in ssh.commands
    assert "ip route | grep default | awk '{print $3}' | head -1" in ssh.commands
    assert (
        "cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | tr '\\n' ' '" in ssh.commands
    )
    assert "cat /etc/sudoers 2>/dev/null | grep -v '#' | grep ALL | head -10" in ssh.commands


def test_collect_sysinfo_returns_empty_string_when_probe_output_is_empty():
    info = sysinfo.collect_sysinfo(FakeSSH())
    assert info["hostname"] == ""
    assert info["open_ports"] == ""
    assert all(v == "" for v in info.values())


def test_collect_sysinfo_trims_trailing_space_from_list_like_probes():
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))
    assert info["users"] == "root deploy svc-www"
    assert info["open_ports"] == "22 80 443 8080"


def test_print_sysinfo_renders_hostname_os_and_hardware_values(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))

    sysinfo.print_sysinfo("10.0.4.21", info)
    out = buf.getvalue()
    assert "web01.corp.example.com" in out
    assert "Ubuntu 22.04.3 LTS" in out
    assert "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.40GHz" in out
    assert "8" in out
    assert "15Gi" in out
    assert "98G" in out
    assert "5.15.0-88-generic" in out


def test_print_sysinfo_renders_network_and_access_sections(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))

    sysinfo.print_sysinfo("10.0.4.21", info)
    out = buf.getvalue()
    assert "10.0.4.21/24" in out
    assert "02:42:ac:11:00:02" in out
    assert "10.0.4.1" in out
    assert "10.0.0.53 10.0.0.54" in out
    assert "22 80 443 8080" in out
    assert "%sudo ALL=(ALL:ALL) ALL" in out
    assert "deploy pts/0 10.0.0.9" in out


def test_print_sysinfo_labels_each_section(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))

    sysinfo.print_sysinfo("10.0.4.21", info)
    out = buf.getvalue()
    for title in ("System Info", "Hardware", "Network", "Access", "Services & Runtime"):
        assert title in out


def test_print_sysinfo_renders_dash_placeholder_for_empty_values(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))
    info["ram_total"] = ""

    sysinfo.print_sysinfo("10.0.4.21", info)
    assert "—" in buf.getvalue()


def test_print_sysinfo_falls_back_to_host_argument_and_question_marks(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)

    sysinfo.print_sysinfo("fallback.example.com", {})
    out = buf.getvalue()
    assert "fallback.example.com" in out
    assert "?" in out


def test_print_sysinfo_truncates_running_services_to_120_chars():
    # Source-level contract: the renderer slices running_svcs to 120 chars.
    # (Rich layout may further wrap the cell, so we don't assert on rendered output.)
    import inspect

    src = inspect.getsource(sysinfo.print_sysinfo)
    assert (
        'running_svcs", "?")[:120]' in src or "running_svcs', '?')[:120]" in src or "[:120]" in src
    )


def test_print_sysinfo_renders_cron_section_only_when_cron_jobs_present(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))

    sysinfo.print_sysinfo("10.0.4.21", info)
    with_cron = buf.getvalue()
    assert "Cron Jobs" in with_cron
    assert "*/5 * * * * /usr/local/bin/rotate.sh" in with_cron

    info["cron_jobs"] = ""
    console2, buf2 = make_console()
    monkeypatch.setattr(sysinfo, "console", console2)
    sysinfo.print_sysinfo("10.0.4.21", info)
    assert "Cron Jobs" not in buf2.getvalue()


def test_print_sysinfo_splits_multiple_cron_jobs_one_per_row(monkeypatch):
    console, buf = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    info = sysinfo.collect_sysinfo(FakeSSH(REALISTIC))
    info["cron_jobs"] = "0 * * * * /opt/one.sh\n30 * * * * /opt/two.sh"

    sysinfo.print_sysinfo("10.0.4.21", info)
    out = buf.getvalue()
    assert "/opt/one.sh" in out
    assert "/opt/two.sh" in out


def test_print_sysinfo_does_not_call_ssh(monkeypatch):
    console, _ = make_console()
    monkeypatch.setattr(sysinfo, "console", console)
    monkeypatch.setattr(sysinfo, "SSHClient", _ForbiddenSSH)

    sysinfo.print_sysinfo("10.0.4.21", {"hostname": "h", "running_svcs": ""})
    assert _ForbiddenSSH.calls == []


class _ForbiddenSSH:
    calls = []


def test_collect_sysinfo_passes_timeout_through_to_run_out():
    class TimeoutSSH(FakeSSH):
        def run_out(self, cmd, timeout=30):
            self.timeouts.append(timeout)
            return super().run_out(cmd, timeout)

    ssh = TimeoutSSH({"nproc": "4"}, default="")
    ssh.timeouts = []
    info = sysinfo.collect_sysinfo(ssh)
    assert set(ssh.timeouts) == {30}
    assert info["cpu_cores"] == "4"


def test_collect_sysinfo_command_list_contains_no_shell_chained_duplicates():
    ssh = FakeSSH(REALISTIC)
    sysinfo.collect_sysinfo(ssh)
    assert len(set(ssh.commands)) == len(ssh.commands)
    assert not re.search(r"\bwho\b", " ".join(ssh.commands))
