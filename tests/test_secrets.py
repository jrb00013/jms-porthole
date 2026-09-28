"""Unit tests for porthole.secrets — pattern matching and the remote grep pipeline.

No real SSH: `secrets.SSHClient` is replaced with a recording fake that serves
canned file listings and file contents.
"""

import re
from io import StringIO

import pytest
from rich.console import Console

from porthole import secrets


def matches(pattern_name, text):
    return bool(re.search(secrets.SECRET_PATTERNS[pattern_name], text))


def matching_types(text):
    return sorted(n for n in secrets.SECRET_PATTERNS if matches(n, text))


# --- AWS Access Key -----------------------------------------------------------

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AKIA + 16 uppercase alnum


def test_aws_access_key_pattern_matches_realistic_key():
    assert matches("AWS Access Key", f"aws_access_key_id = {AWS_KEY}")


def test_aws_access_key_pattern_matches_key_embedded_in_log_line():
    assert matches("AWS Access Key", f"2024-01-01 auth error for key {AWS_KEY} denied")


def test_aws_access_key_pattern_rejects_lowercase_variant():
    assert not matches("AWS Access Key", AWS_KEY.lower())


def test_aws_access_key_pattern_rejects_too_short_key():
    assert not matches("AWS Access Key", "AKIA1234567")


def test_aws_access_key_pattern_matches_first_16_chars_of_longer_run():
    """The pattern is unanchored, so a longer all-caps run still matches."""
    assert matches("AWS Access Key", "AKIA" + "A" * 17)


def test_aws_access_key_pattern_rejects_uuid():
    assert not matches("AWS Access Key", "0f8fad5b-d9cb-469f-a165-70867728950e")


def test_aws_access_key_pattern_rejects_asia_temporary_prefix():
    assert not matches("AWS Access Key", "ASIAIOSFODNN7EXAMPLE")


# --- AWS Secret ---------------------------------------------------------------

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars


def test_aws_secret_matches_underscore_key_equals_value():
    assert matches("AWS Secret", f"aws_secret = '{AWS_SECRET}'")


def test_aws_secret_matches_dashed_key_colon_value():
    assert matches("AWS Secret", f"aws-secret: {AWS_SECRET}")


def test_aws_secret_matches_case_insensitively():
    assert matches("AWS Secret", f"AWS_SECRET={AWS_SECRET}")


def test_aws_secret_rejects_39_char_value():
    assert not matches("AWS Secret", f"aws_secret = '{AWS_SECRET[:39]}'")


def test_aws_secret_rejects_word_secret_without_aws_prefix():
    assert not matches("AWS Secret", f"secret = '{AWS_SECRET}'")


def test_aws_secret_rejects_missing_separator_before_value():
    assert not matches("AWS Secret", f"aws_secret {AWS_SECRET}")


# --- GitHub / GitLab / Slack tokens -------------------------------------------


def test_github_token_matches_ghp_prefix_plus_36_chars():
    assert matches("GitHub Token", "ghp_" + "A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz"[:36])


def test_github_token_matches_40_char_token():
    assert matches("GitHub Token", "ghp_" + "a" * 36)


def test_github_token_rejects_short_token():
    assert not matches("GitHub Token", "ghp_" + "a" * 10)


def test_github_token_rejects_wrong_prefix():
    assert not matches("GitHub Token", "gho_" + "a" * 36)


def test_github_token_rejects_uuid():
    assert not matches("GitHub Token", "550e8400-e29b-41d4-a716-446655440000")


def test_gitlab_token_matches_glpat_prefix():
    assert matches("GitLab Token", "glpat-" + "ABCDEFGHIJKLMNOPQRST")


def test_gitlab_token_rejects_short_glpat():
    assert not matches("GitLab Token", "glpat-short")


def test_gitlab_token_rejects_bearer_token():
    assert not matches("GitLab Token", "Bearer abcdefghijklmnopqrstuvwx")


def test_slack_token_matches_bot_token():
    # Build at runtime so the file never contains a GitHub-detectable Slack token literal.
    token = "xoxb-" + "-".join(["1234567890", "1234567890123", "AbCdEfGhIjKlMnOpQrStUvWx"])
    assert matches("Slack Token", token)


def test_slack_token_matches_user_token():
    token = "xoxp-" + "-".join(["1234567890", "abcdefghij"])
    assert matches("Slack Token", token)


def test_slack_token_rejects_unknown_letter_prefix():
    assert not matches("Slack Token", "xoxz-" + "-".join(["1234567890", "abcdefghij"]))


def test_slack_token_rejects_short_suffix():
    assert not matches("Slack Token", "xoxb-123")


# --- Private key headers ------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_private_key_pattern_matches_key_headers(header):
    assert matches("Private Key", header)


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN RSA PUBLIC KEY-----",
        "BEGIN PRIVATE KEY",
    ],
)
def test_private_key_pattern_rejects_non_private_key_headers(header):
    assert not matches("Private Key", header)


# --- Generic API key ----------------------------------------------------------


def test_generic_api_key_matches_api_key_assignment():
    assert matches("Generic API Key", 'api_key = "abcdef0123456789abcdef"')


def test_generic_api_key_matches_apikey_without_separator():
    assert matches("Generic API Key", "apikey=abcdefghijklmnopqrst")


def test_generic_api_key_matches_api_secret_assignment():
    assert matches("Generic API Key", "api_secret: xyz0123456789abcdef")


def test_generic_api_key_matches_dashed_api_key_label():
    assert matches("Generic API Key", "api-key = 'ZZZZZZZZZZZZZZZZZZZZ'")


def test_generic_api_key_rejects_value_shorter_than_16():
    assert not matches("Generic API Key", 'api_key = "short"')


def test_generic_api_key_rejects_word_mentioned_in_prose():
    assert not matches("Generic API Key", "the apikey is stored in vault")


def test_generic_api_key_rejects_md5_hash():
    assert not matches("Generic API Key", "3f2504e04f4c11f1a1b2c3d4e5f67890")


# --- Password in config -------------------------------------------------------


def test_password_in_config_matches_double_quoted_password():
    assert matches("Password in Config", 'password = "hunter2"')


def test_password_in_config_matches_single_quoted_pwd_assignment():
    assert matches("Password in Config", "PWD: 'letmein1'")


def test_password_in_config_matches_passwd_spelling():
    assert matches("Password in Config", 'passwd = "s3cr3t!"')


def test_password_in_config_rejects_unquoted_value():
    assert not matches("Password in Config", "password = hunter2")


def test_password_in_config_rejects_value_shorter_than_four():
    assert not matches("Password in Config", 'password = "abc"')


def test_password_in_config_rejects_placeholder_word():
    assert not matches("Password in Config", "password = %PASSWORD%")


# --- JWT ----------------------------------------------------------------------

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_jwt_pattern_matches_three_segment_token():
    assert matches("JWT", f"Authorization: Bearer {JWT}")


def test_jwt_pattern_rejects_truncated_token():
    assert not matches("JWT", "eyJhbGci.eyJzdWI.SflKxw")


def test_jwt_pattern_rejects_base64_blob_without_leading_eyJ():
    """A long base64 blob is not a JWT — the eyJ header prefix is required."""
    assert not matches("JWT", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5")


def test_jwt_pattern_rejects_two_segment_token():
    assert not matches("JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw")


# --- Database URL -------------------------------------------------------------


def test_database_url_matches_mysql_connection_string():
    assert matches("Database URL", "mysql://root:pw@10.0.0.1:3306/appdb")


def test_database_url_matches_mongodb_uri():
    assert matches("Database URL", "mongodb://user:pw@mongo.internal:27017/db")


def test_database_url_matches_redis_uri_case_insensitively():
    assert matches("Database URL", "REDIS://cache.internal:6379/0")


def test_database_url_matches_postgres_uri():
    assert matches("Database URL", "postgres://u:p@db.internal:5432/app")


def test_database_url_rejects_plain_hostname():
    assert not matches("Database URL", "psql -h db.example.com -U admin")


def test_database_url_rejects_scheme_without_credentials_or_path():
    assert not matches("Database URL", "https://db.example.com/health")


def test_database_url_rejects_short_random_string():
    assert not matches("Database URL", "x9f2")


# --- Cross-pattern sanity -----------------------------------------------------


def test_base64_blob_does_not_match_any_pattern():
    blob = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGUgcG9w"
    assert matching_types(blob) == []


def test_uuid_does_not_match_any_pattern():
    assert matching_types("3f2504e0-4f89-11d3-9a0c-0305e82c3301") == []


def test_short_random_hex_string_does_not_match_any_pattern():
    assert matching_types("deadbeef") == []


def test_normal_nginx_config_line_does_not_match_any_pattern():
    line = "    worker_processes  auto;"
    assert matching_types(line) == []


def test_git_commit_hash_line_does_not_match_any_pattern():
    line = "commit 3f2504e04f4c11f1a1b2c3d4e5f6789012345678"
    assert matching_types(line) == []


def test_aws_key_also_trips_generic_api_key_via_key_id_label():
    """`aws_access_key_id` contains `key` but not `api_key`, so only AWS matches."""
    line = f"aws_access_key_id = {AWS_KEY}"
    assert "AWS Access Key" in matching_types(line)
    assert "Generic API Key" not in matching_types(line)


# --- _build_grep_cmd ----------------------------------------------------------


def test_build_grep_cmd_without_extensions_uses_size_limit_only():
    cmd = secrets._build_grep_cmd(["/etc", "/home"])
    assert cmd == f"find /etc /home -type f -size -{secrets.MAX_FILE_SIZE}c 2>/dev/null"


def test_build_grep_cmd_with_extensions_builds_name_predicates():
    cmd = secrets._build_grep_cmd(["/srv"], extensions="py,conf")
    assert cmd == (
        f"find /srv -type f \\( -name '*.py' -o -name '*.conf' \\) "
        f"-size -{secrets.MAX_FILE_SIZE}c 2>/dev/null"
    )


def test_build_grep_cmd_single_extension_has_no_trailing_or():
    cmd = secrets._build_grep_cmd(["/opt"], extensions="env")
    assert "-o" not in cmd
    assert "\\( -name '*.env' \\)" in cmd


def test_build_grep_cmd_max_file_size_is_one_megabyte():
    cmd = secrets._build_grep_cmd(["/etc"])
    assert "-size -1048576c" in cmd
    assert secrets.MAX_FILE_SIZE == 1_048_576


def test_build_grep_cmd_empty_path_list_yields_bare_find():
    assert secrets._build_grep_cmd([]) == (
        f"find  -type f -size -{secrets.MAX_FILE_SIZE}c 2>/dev/null"
    )


# --- scan_remote with a recording fake SSH client ------------------------------


class FakeSSHClient:
    """Stands in for porthole.ssh.SSHClient; records every command requested.

    Configure the canned filesystem with `files` (newline-joined listing) and
    `contents` (path -> file text) before calling scan_remote.
    """

    files = ""
    contents = {}
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
        if cmd.startswith("find "):
            return type(self).files, "", 0
        if cmd.startswith("cat '"):
            path = cmd.split("cat '", 1)[1].split("'", 1)[0]
            return type(self).contents.get(path, ""), "", 0
        raise AssertionError(f"unexpected command: {cmd}")

    def run_out(self, cmd, timeout=30):
        return self.run(cmd, timeout=timeout)[0]


@pytest.fixture
def fake_ssh(monkeypatch):
    FakeSSHClient.instances = []
    FakeSSHClient.files = ""
    FakeSSHClient.contents = {}
    monkeypatch.setattr(secrets, "SSHClient", FakeSSHClient)
    return FakeSSHClient


def test_scan_remote_uses_default_paths_when_none_given(fake_ssh):
    secrets.scan_remote("h", "u", "p")
    find_cmd = FakeSSHClient.instances[0].commands[0][0]
    for p in secrets.DEFAULT_PATHS:
        assert p in find_cmd


def test_scan_remote_limits_file_listing_to_max_files(fake_ssh):
    secrets.scan_remote("h", "u", "p", max_files=7)
    assert FakeSSHClient.instances[0].commands[0][0].endswith("| head -7")


def test_scan_remote_uses_custom_paths_and_extensions(fake_ssh):
    secrets.scan_remote("h", "u", "p", paths=["/custom"], extensions="env,toml")
    find_cmd = FakeSSHClient.instances[0].commands[0][0]
    assert "/custom" in find_cmd
    assert "-name '*.env'" in find_cmd and "-name '*.toml'" in find_cmd


def test_scan_remote_returns_empty_list_when_no_files_found(fake_ssh):
    assert secrets.scan_remote("h", "u", "p") == []


def test_scan_remote_finds_aws_key_with_file_line_and_type(fake_ssh):
    fake_ssh.files = "/opt/app/.env"
    fake_ssh.contents = {"/opt/app/.env": f"AWS_KEY={AWS_KEY}"}

    findings = secrets.scan_remote("h", "u", "p")
    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Access Key"
    assert findings[0]["file"] == "/opt/app/.env"
    assert findings[0]["line"] == 1
    assert AWS_KEY in findings[0]["snippet"]


def test_scan_remote_line_numbers_are_one_based(fake_ssh):
    fake_ssh.files = "/etc/creds"
    fake_ssh.contents = {"/etc/creds": f"\n\ntoken=ghp_{'a' * 36}"}

    findings = secrets.scan_remote("h", "u", "p")
    assert [f["line"] for f in findings] == [3]


def test_scan_remote_cats_each_file_with_quoted_path_and_10s_timeout(fake_ssh):
    fake_ssh.files = "/opt/a.env\n/opt/b.env"
    fake_ssh.contents = {"/opt/a.env": "nothing here", "/opt/b.env": "nothing here"}

    secrets.scan_remote("h", "u", "p", paths=["/opt"])
    cat_cmds = [c for c in FakeSSHClient.instances[0].commands if c[0].startswith("cat ")]
    assert cat_cmds[0] == ("cat '/opt/a.env' 2>/dev/null", 10)
    assert cat_cmds[1] == ("cat '/opt/b.env' 2>/dev/null", 10)


def test_scan_remote_runs_one_cat_per_file_per_pattern(fake_ssh):
    """Every pattern re-reads every file, so count == files * patterns."""
    fake_ssh.files = "/opt/a.env\n/opt/b.env"
    fake_ssh.contents = {"/opt/a.env": "x = 1", "/opt/b.env": "y = 2"}

    secrets.scan_remote("h", "u", "p", paths=["/opt"])
    cats = [c for c in FakeSSHClient.instances[0].commands if c[0].startswith("cat ")]
    assert len(cats) == 2 * len(secrets.SECRET_PATTERNS)


def test_scan_remote_skips_empty_file_contents(fake_ssh):
    fake_ssh.files = "/opt/empty.env"
    fake_ssh.contents = {}

    assert secrets.scan_remote("h", "u", "p", paths=["/opt"]) == []


def test_scan_remote_finds_secrets_across_multiple_files(fake_ssh):
    fake_ssh.files = "/opt/a.env\n/opt/b.env"
    fake_ssh.contents = {
        "/opt/a.env": f"AWS={AWS_KEY}",
        "/opt/b.env": f"GH=ghp_{'b' * 36}",
    }

    findings = secrets.scan_remote("h", "u", "p", paths=["/opt"])
    assert {f["file"] for f in findings} == {"/opt/a.env", "/opt/b.env"}


def test_scan_remote_reports_one_finding_per_matching_line(fake_ssh):
    fake_ssh.files = "/opt/a.env"
    fake_ssh.contents = {
        "/opt/a.env": f"AWS={AWS_KEY}\nGH=ghp_{'c' * 36}\nNOTHING=1",
    }

    findings = secrets.scan_remote("h", "u", "p", paths=["/opt"])
    assert sorted(f["type"] for f in findings) == ["AWS Access Key", "GitHub Token"]
    assert sorted(f["line"] for f in findings) == [1, 2]


def test_scan_remote_truncates_snippet_to_120_chars(fake_ssh):
    fake_ssh.files = "/opt/long.env"
    long_line = f"AWS={AWS_KEY} trailing=" + "x" * 300
    fake_ssh.contents = {"/opt/long.env": f"harmless=1\n{long_line}"}

    findings = secrets.scan_remote("h", "u", "p", paths=["/opt"])
    assert len(findings) == 1
    assert len(findings[0]["snippet"]) == 120
    assert findings[0]["line"] == 2


def test_scan_remote_strips_whitespace_from_snippet(fake_ssh):
    fake_ssh.files = "/opt/padded.env"
    fake_ssh.contents = {"/opt/padded.env": f"   AWS={AWS_KEY}   "}

    findings = secrets.scan_remote("h", "u", "p", paths=["/opt"])
    assert findings[0]["snippet"] == f"AWS={AWS_KEY}"


def test_scan_remote_ignores_blank_lines_in_file_listing(fake_ssh):
    fake_ssh.files = "/opt/a.env\n\n   \n/opt/b.env"
    fake_ssh.contents = {}

    secrets.scan_remote("h", "u", "p", paths=["/opt"])
    cats = {c[0] for c in FakeSSHClient.instances[0].commands if c[0].startswith("cat ")}
    assert cats == {"cat '/opt/a.env' 2>/dev/null", "cat '/opt/b.env' 2>/dev/null"}


def test_scan_remote_connects_and_disconnects_the_ssh_client(fake_ssh):
    secrets.scan_remote("h", "u", "p")
    client = FakeSSHClient.instances[0]
    assert client.connected is True
    assert client.disconnected is True
    assert (client.host, client.username, client.password) == ("h", "u", "p")


# --- print_secret_results -----------------------------------------------------


def _capture_console(monkeypatch, module):
    buf = StringIO()
    monkeypatch.setattr(module, "console", Console(file=buf, width=200, no_color=True))
    return buf


def test_print_secret_results_greets_when_no_findings(monkeypatch):
    buf = _capture_console(monkeypatch, secrets)
    secrets.print_secret_results("clean.example.com", [])
    out = buf.getvalue()
    assert "No secrets found" in out
    assert "clean.example.com" in out


def test_print_secret_results_lists_finding_count_in_title(monkeypatch):
    buf = _capture_console(monkeypatch, secrets)
    secrets.print_secret_results(
        "h",
        [
            {"type": "AWS Access Key", "file": "/a", "line": 1, "snippet": "s"},
            {"type": "GitHub Token", "file": "/b", "line": 2, "snippet": "t"},
        ],
    )
    assert "2 findings" in buf.getvalue()


def test_print_secret_results_prints_type_file_and_snippet(monkeypatch):
    buf = _capture_console(monkeypatch, secrets)
    secrets.print_secret_results(
        "h",
        [
            {"type": "AWS Access Key", "file": "/opt/app/.env", "line": 42, "snippet": "AWS=x"},
        ],
    )
    out = buf.getvalue()
    assert "AWS Access Key" in out
    assert "/opt/app/.env" in out
    assert "42" in out


def test_print_secret_results_handles_single_finding_singular_title(monkeypatch):
    buf = _capture_console(monkeypatch, secrets)
    secrets.print_secret_results(
        "h",
        [
            {"type": "JWT", "file": "/a", "line": 1, "snippet": "s"},
        ],
    )
    assert "1 findings" in buf.getvalue()
