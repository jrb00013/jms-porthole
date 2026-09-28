"""Unit tests for porthole.creds — default credential table and wordlist loading."""

import pytest

from porthole import creds


def test_default_credentials_contains_twenty_unique_pairs():
    assert len(creds.DEFAULT_CREDENTIALS) == 20
    assert len(set(creds.DEFAULT_CREDENTIALS)) == 20


def test_default_credentials_includes_admin_password_and_root_root():
    assert ("admin", "admin") in creds.DEFAULT_CREDENTIALS
    assert ("admin", "password") in creds.DEFAULT_CREDENTIALS
    assert ("root", "root") in creds.DEFAULT_CREDENTIALS
    assert ("root", "toor") in creds.DEFAULT_CREDENTIALS


def test_default_credentials_includes_blank_password_entries():
    assert ("admin", "") in creds.DEFAULT_CREDENTIALS
    assert ("root", "") in creds.DEFAULT_CREDENTIALS


def test_default_credentials_includes_raspberry_pi_and_vendor_defaults():
    assert ("pi", "raspberry") in creds.DEFAULT_CREDENTIALS
    assert ("ubuntu", "ubuntu") in creds.DEFAULT_CREDENTIALS
    assert ("guest", "guest") in creds.DEFAULT_CREDENTIALS
    assert ("administrator", "administrator") in creds.DEFAULT_CREDENTIALS


def test_default_credentials_contain_no_missing_values():
    for user, password in creds.DEFAULT_CREDENTIALS:
        assert user
        assert isinstance(password, str)


def test_wordlist_usernames_repeat_entries_in_pair_order():
    """Quirk: usernames are NOT deduplicated (passwordes are). 'admin' appears 6x."""
    assert creds.WORDLIST_USERNAMES == [u for u, _ in creds.DEFAULT_CREDENTIALS]
    assert len(creds.WORDLIST_USERNAMES) == len(creds.DEFAULT_CREDENTIALS) == 20
    assert creds.WORDLIST_USERNAMES.count("admin") == 6
    assert creds.WORDLIST_USERNAMES.count("root") == 4
    assert creds.WORDLIST_USERNAMES[0] == "admin"
    assert creds.WORDLIST_USERNAMES[-1] == "administrator"


def test_wordlist_usernames_deduped_to_eleven_distinct_names():
    assert list(dict.fromkeys(creds.WORDLIST_USERNAMES)) == [
        "admin",
        "root",
        "user",
        "ubuntu",
        "pi",
        "guest",
        "test",
        "support",
        "service",
        "operator",
        "administrator",
    ]


def test_wordlist_usernames_match_the_first_element_of_each_pair():
    assert creds.WORDLIST_USERNAMES == [u for u, _ in creds.DEFAULT_CREDENTIALS]


def test_wordlist_passwords_are_deduplicated_in_first_seen_order():
    assert creds.WORDLIST_PASSWORDS == [
        "admin",
        "password",
        "1234",
        "12345",
        "123456",
        "",
        "root",
        "toor",
        "user",
        "ubuntu",
        "raspberry",
        "guest",
        "test",
        "support",
        "service",
        "operator",
        "administrator",
    ]
    assert len(creds.WORDLIST_PASSWORDS) == len(set(creds.WORDLIST_PASSWORDS))


def test_wordlist_passwords_include_the_blank_password_exactly_once():
    assert creds.WORDLIST_PASSWORDS.count("") == 1
    assert creds.WORDLIST_PASSWORDS[5] == ""


def test_wordlist_passwords_have_no_missing_values():
    assert None not in creds.WORDLIST_PASSWORDS
    assert all(isinstance(p, str) for p in creds.WORDLIST_PASSWORDS)


def test_load_wordlist_strips_whitespace_and_drops_blank_and_comment_lines(tmp_path):
    path = tmp_path / "wordlist.txt"
    path.write_text("# a comment\nroot\n  admin  \n\n\t# indented-looking\npassword\n")

    assert creds.load_wordlist(str(path)) == ["root", "admin", "# indented-looking", "password"]


def test_load_wordlist_keeps_comments_with_leading_whitespace(tmp_path):
    """Quirk: the comment check runs before .strip(), so '  # x' survives as '# x'."""
    path = tmp_path / "wordlist.txt"
    path.write_text("  # spaced comment\nroot\n")

    assert creds.load_wordlist(str(path)) == ["# spaced comment", "root"]


def test_load_wordlist_returns_empty_list_for_file_of_only_comments(tmp_path):
    path = tmp_path / "wordlist.txt"
    path.write_text("#only\n#comments\n\n   \n")

    assert creds.load_wordlist(str(path)) == []


def test_load_wordlist_returns_empty_list_for_empty_file(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("")

    assert creds.load_wordlist(str(path)) == []


def test_load_wordlist_preserves_duplicates_and_order(tmp_path):
    path = tmp_path / "dupes.txt"
    path.write_text("root\nadmin\nroot\n")

    assert creds.load_wordlist(str(path)) == ["root", "admin", "root"]


def test_load_wordlist_keeps_internal_whitespace_within_an_entry(tmp_path):
    path = tmp_path / "spaced.txt"
    path.write_text("  pass word  \n")

    assert creds.load_wordlist(str(path)) == ["pass word"]


def test_load_wordlist_raises_file_not_found_for_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        creds.load_wordlist(str(tmp_path / "nope.txt"))


def test_load_wordlist_keeps_empty_password_line_dropped(tmp_path):
    path = tmp_path / "pw.txt"
    path.write_text("root\n\nadmin\n")

    assert creds.load_wordlist(str(path)) == ["root", "admin"]


def test_default_username_wordlist_covers_every_default_credential_user():
    for user, _ in creds.DEFAULT_CREDENTIALS:
        assert user in creds.WORDLIST_USERNAMES
