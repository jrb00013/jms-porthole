"""Unit tests for porthole.vuln — _assess severity logic and the SSH check pipeline."""

from io import StringIO

import pytest
from rich.console import Console

from porthole import vuln

# --- _assess: upgradable_packages --------------------------------------------


@pytest.mark.parametrize(
    "raw,severity",
    [
        ("0", "low"),
        ("1", "low"),
        ("10", "low"),
        ("11", "medium"),
        ("50", "medium"),
        ("51", "high"),
        ("500", "high"),
    ],
)
def test_assess_upgradable_packages_severity_by_count(raw, severity):
    sev, _ = vuln._assess("upgradable_packages", raw)
    assert sev == severity


def test_assess_upgradable_packages_detail_includes_count():
    assert vuln._assess("upgradable_packages", "12")[1] == "12 packages need updates"


def test_assess_upgradable_packages_non_numeric_output_counts_zero():
    sev, detail = vuln._assess("upgradable_packages", "")
    assert sev == "low"
    assert detail == "0 packages need updates"


def test_assess_upgradable_packages_apt_multiline_error_output_counts_zero():
    sev, _ = vuln._assess("upgradable_packages", "E: Unable to locate package")
    assert sev == "low"


def test_assess_upgradable_packages_surrounding_whitespace_is_stripped():
    sev, detail = vuln._assess("upgradable_packages", "  60 \n")
    assert sev == "high"
    assert detail == "60 packages need updates"


# --- _assess: root_login -------------------------------------------------------


def test_assess_root_login_yes_is_high():
    sev, detail = vuln._assess("root_login", "PermitRootLogin yes")
    assert sev == "high"
    assert detail == "PermitRootLogin yes"


def test_assess_root_login_no_is_low():
    assert vuln._assess("root_login", "PermitRootLogin no")[0] == "low"


def test_assess_root_login_without_password_is_low():
    assert vuln._assess("root_login", "PermitRootLogin without-password")[0] == "low"


def test_assess_root_login_prohibit_password_is_low():
    assert vuln._assess("root_login", "PermitRootLogin prohibit-password")[0] == "low"


def test_assess_root_login_not_found_string_is_low_and_passes_detail_through():
    sev, detail = vuln._assess("root_login", "not found")
    assert sev == "low"
    assert detail == "not found"


def test_assess_root_login_yes_is_matched_case_insensitively():
    assert vuln._assess("root_login", "permitrootlogin YES")[0] == "high"


def test_assess_root_login_empty_output_is_low():
    assert vuln._assess("root_login", "")[0] == "low"


# --- _assess: password_auth ----------------------------------------------------


def test_assess_password_auth_yes_is_medium_not_high():
    sev, detail = vuln._assess("password_auth", "PasswordAuthentication yes")
    assert sev == "medium"
    assert detail == "PasswordAuthentication yes"


def test_assess_password_auth_no_is_low():
    assert vuln._assess("password_auth", "PasswordAuthentication no")[0] == "low"


def test_assess_password_auth_not_found_is_low():
    assert vuln._assess("password_auth", "not found")[0] == "low"


# --- _assess: empty_passwords --------------------------------------------------


def test_assess_empty_passwords_zero_is_low_none_found():
    assert vuln._assess("empty_passwords", "0") == ("low", "none found")


@pytest.mark.parametrize("raw", ["1", "2", "17"])
def test_assess_empty_passwords_any_count_is_critical(raw):
    sev, detail = vuln._assess("empty_passwords", raw)
    assert sev == "critical"
    assert detail == f"{raw} accounts with empty passwords"


def test_assess_empty_passwords_non_numeric_is_low_none_found():
    assert vuln._assess("empty_passwords", "Permission denied") == ("low", "none found")


# --- _assess: world_writable --------------------------------------------------


def test_assess_world_writable_under_threshold_is_low():
    sev, detail = vuln._assess("world_writable", "4")
    assert (sev, detail) == ("low", "4 found")


def test_assess_world_writable_exactly_20_is_low():
    assert vuln._assess("world_writable", "20")[0] == "low"


def test_assess_world_writable_over_20_is_medium():
    sev, detail = vuln._assess("world_writable", "21")
    assert sev == "medium"
    assert detail == "21 world-writable files"


def test_assess_world_writable_garbage_output_counts_zero():
    assert vuln._assess("world_writable", "find: /tmp: No such file or directory") == (
        "low",
        "0 found",
    )


# --- _assess: suid_binaries ---------------------------------------------------


def test_assess_suid_binaries_exactly_30_is_low():
    assert vuln._assess("suid_binaries", "30")[0] == "low"


def test_assess_suid_binaries_over_30_is_medium():
    sev, detail = vuln._assess("suid_binaries", "31")
    assert sev == "medium"
    assert detail == "31 SUID binaries"


def test_assess_suid_binaries_garbage_output_counts_zero():
    assert vuln._assess("suid_binaries", "") == ("low", "0 found")


# --- _assess: last_logins -----------------------------------------------------


@pytest.mark.parametrize(
    "raw,severity",
    [
        ("0", "low"),
        ("20", "low"),
        ("21", "medium"),
        ("100", "medium"),
        ("101", "high"),
    ],
)
def test_assess_last_logins_severity_by_failed_attempt_count(raw, severity):
    sev, detail = vuln._assess("last_logins", raw)
    assert sev == severity
    assert detail == f"{raw} failed attempts"


def test_assess_last_logins_garbage_output_counts_zero():
    assert vuln._assess("last_logins", "journalctl: no journal files") == (
        "low",
        "0 failed attempts",
    )


# --- _assess: unclassified checks ---------------------------------------------


def test_assess_kernel_version_is_info_with_raw_value():
    assert vuln._assess("kernel_version", "6.1.0-18-amd64") == ("info", "6.1.0-18-amd64")


def test_assess_listening_ports_is_info_with_raw_value():
    assert vuln._assess("listening_ports", "4")[0] == "info"


def test_assess_ufw_status_is_info_with_raw_value():
    assert vuln._assess("ufw_status", "Status: active")[0] == "info"


def test_assess_unknown_check_detail_truncated_to_80_chars():
    long_raw = "x" * 200
    sev, detail = vuln._assess("mystery_check", long_raw)
    assert sev == "info"
    assert len(detail) == 80


# --- CHECKS table -------------------------------------------------------------


def test_checks_table_has_expected_keys_in_order():
    keys = [k for k, _, _ in vuln.CHECKS]
    assert keys == [
        "upgradable_packages",
        "root_login",
        "password_auth",
        "empty_passwords",
        "world_writable",
        "suid_binaries",
        "listening_ports",
        "ufw_status",
        "kernel_version",
        "last_logins",
    ]


def test_checks_table_has_unique_labels():
    labels = [label for _, label, _ in vuln.CHECKS]
    assert len(labels) == len(set(labels))


def test_checks_table_commands_are_all_non_empty():
    assert all(cmd.strip() for _, _, cmd in vuln.CHECKS)


# --- run_vuln_checks with a recording fake SSH client --------------------------


class FakeSSHClient:
    """Stands in for porthole.ssh.SSHClient; serves canned per-command output."""

    outputs = {}
    failures = {}
    instances = []

    def __init__(self, host="h", username="u", password=None, **kwargs):
        self.host = host
        self.username = username
        self.password = password
        self.commands = []
        self.connected = False
        self.disconnected = False
        FakeSSHClient.instances.append(self)

    def __enter__(self):
        self.connected = True
        return self

    def __exit__(self, *_):
        self.disconnected = True
        return False

    def run(self, cmd, timeout=30):
        self.commands.append((cmd, timeout))
        if cmd in type(self).failures:
            return "", type(self).failures[cmd], 1
        return type(self).outputs.get(cmd, ""), "", 0

    def run_out(self, cmd, timeout=30):
        return self.run(cmd, timeout=timeout)[0]


@pytest.fixture
def fake_ssh(monkeypatch):
    FakeSSHClient.instances = []
    FakeSSHClient.outputs = {}
    FakeSSHClient.failures = {}
    monkeypatch.setattr(vuln, "SSHClient", FakeSSHClient)
    return FakeSSHClient


def test_run_vuln_checks_issues_every_check_command_exactly_once(fake_ssh):
    results = vuln.run_vuln_checks("h", "u", "p")
    issued = [c for c, _ in FakeSSHClient.instances[0].commands]
    assert issued == [cmd for _, _, cmd in vuln.CHECKS]
    assert len(results) == len(vuln.CHECKS)


def test_run_vuln_checks_gives_each_check_a_60_second_timeout(fake_ssh):
    vuln.run_vuln_checks("h", "u", "p")
    assert all(t == 60 for _, t in FakeSSHClient.instances[0].commands)


def test_run_vuln_checks_labels_match_the_checks_table(fake_ssh):
    results = vuln.run_vuln_checks("h", "u", "p")
    assert [r["check"] for r in results] == [label for _, label, _ in vuln.CHECKS]


def test_run_vuln_checks_empty_output_yields_low_or_info_not_critical(fake_ssh):
    results = vuln.run_vuln_checks("h", "u", "p")
    assert all(r["severity"] != "critical" for r in results)
    assert all(r["raw"] == "" for r in results)


def test_run_vuln_checks_flags_empty_passwords_as_critical(fake_ssh):
    cmd = next(c for k, _, c in vuln.CHECKS if k == "empty_passwords")
    fake_ssh.outputs[cmd] = "2"
    results = vuln.run_vuln_checks("h", "u", "p")
    empty = next(r for r in results if r["check"] == "Empty password accounts")
    assert empty["severity"] == "critical"
    assert empty["detail"] == "2 accounts with empty passwords"


def test_run_vuln_checks_flags_root_login_yes_as_high(fake_ssh):
    cmd = next(c for k, _, c in vuln.CHECKS if k == "root_login")
    fake_ssh.outputs[cmd] = "PermitRootLogin yes"
    results = vuln.run_vuln_checks("h", "u", "p")
    root = next(r for r in results if r["check"] == "SSH PermitRootLogin")
    assert root["severity"] == "high"
    assert root["raw"] == "PermitRootLogin yes"


def test_run_vuln_checks_reports_kernel_version_as_info(fake_ssh):
    cmd = next(c for k, _, c in vuln.CHECKS if k == "kernel_version")
    fake_ssh.outputs[cmd] = "6.1.0-18-amd64"
    results = vuln.run_vuln_checks("h", "u", "p")
    kern = next(r for r in results if r["check"] == "Kernel version")
    assert kern["severity"] == "info"
    assert kern["detail"] == "6.1.0-18-amd64"


def test_run_vuln_checks_truncates_raw_output_to_200_chars(fake_ssh):
    cmd = next(c for k, _, c in vuln.CHECKS if k == "kernel_version")
    fake_ssh.outputs[cmd] = "k" * 500
    results = vuln.run_vuln_checks("h", "u", "p")
    kern = next(r for r in results if r["check"] == "Kernel version")
    assert len(kern["raw"]) == 200


def test_run_vuln_checks_treats_failed_command_stderr_as_empty_output(fake_ssh):
    """A non-zero exit yields no stdout, so the check is assessed on ''."""
    cmd = next(c for k, _, c in vuln.CHECKS if k == "world_writable")
    fake_ssh.failures[cmd] = "find: /tmp: Permission denied"
    results = vuln.run_vuln_checks("h", "u", "p")
    ww = next(r for r in results if r["check"] == "World-writable files in /tmp")
    assert ww["raw"] == ""
    assert ww["severity"] == "low"
    assert ww["detail"] == "0 found"


def test_run_vuln_checks_not_found_sshd_config_is_low_not_high(fake_ssh):
    results = vuln.run_vuln_checks("h", "u", "p")
    root = next(r for r in results if r["check"] == "SSH PermitRootLogin")
    assert root["severity"] == "low"
    assert root["detail"] == ""


def test_run_vuln_checks_returns_one_result_per_check(fake_ssh):
    assert len(vuln.run_vuln_checks("h", "u", "p")) == len(vuln.CHECKS)


def test_run_vuln_checks_connects_and_disconnects_once(fake_ssh):
    vuln.run_vuln_checks("h", "u", "p")
    assert len(FakeSSHClient.instances) == 1
    client = FakeSSHClient.instances[0]
    assert client.connected is True
    assert client.disconnected is True
    assert (client.host, client.username, client.password) == ("h", "u", "p")


def test_run_vuln_checks_all_results_have_the_four_expected_keys(fake_ssh):
    for result in vuln.run_vuln_checks("h", "u", "p"):
        assert set(result) == {"check", "severity", "detail", "raw"}


# --- print_vuln_results -------------------------------------------------------


def _capture_console(monkeypatch):
    buf = StringIO()
    monkeypatch.setattr(vuln, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_print_vuln_results_prints_check_severity_and_detail(monkeypatch):
    buf = _capture_console(monkeypatch)
    vuln.print_vuln_results(
        "host1",
        [
            {"check": "Kernel version", "severity": "info", "detail": "6.1.0", "raw": ""},
        ],
    )
    out = buf.getvalue()
    assert "Kernel version" in out
    assert "info" in out
    assert "6.1.0" in out


def test_print_vuln_results_counts_critical_and_high_as_alerts(monkeypatch):
    buf = _capture_console(monkeypatch)
    vuln.print_vuln_results(
        "host1",
        [
            {"check": "A", "severity": "critical", "detail": "d", "raw": ""},
            {"check": "B", "severity": "high", "detail": "d", "raw": ""},
            {"check": "C", "severity": "low", "detail": "d", "raw": ""},
        ],
    )
    assert "2 critical/high findings" in buf.getvalue()


def test_print_vuln_medium_and_low_alone_are_not_alerts(monkeypatch):
    buf = _capture_console(monkeypatch)
    vuln.print_vuln_results(
        "host1",
        [
            {"check": "A", "severity": "medium", "detail": "d", "raw": ""},
            {"check": "B", "severity": "low", "detail": "d", "raw": ""},
        ],
    )
    out = buf.getvalue()
    assert "No critical/high findings" in out
    assert "⚠" not in out


def test_print_vuln_results_renders_empty_result_list(monkeypatch):
    buf = _capture_console(monkeypatch)
    vuln.print_vuln_results("host1", [])
    assert "No critical/high findings" in buf.getvalue()


def test_print_vuln_unknown_severity_does_not_raise(monkeypatch):
    buf = _capture_console(monkeypatch)
    vuln.print_vuln_results(
        "host1",
        [
            {"check": "Weird", "severity": "bogus", "detail": "d", "raw": ""},
        ],
    )
    assert "bogus" in buf.getvalue()
