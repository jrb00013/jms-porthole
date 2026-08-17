"""Unit tests for porthole.profiles — uses a tmp_path instead of ~/.porthole."""
from porthole import profiles


def test_save_and_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")

    profiles.save_profile(
        "prod-web",
        hosts=["10.0.0.1", "10.0.0.2"],
        username="deploy",
        ports=[80, 443],
        timeout=15,
        jump_host="bastion.example.com",
    )

    loaded = profiles.load_profile("prod-web")
    assert loaded["hosts"] == ["10.0.0.1", "10.0.0.2"]
    assert loaded["username"] == "deploy"
    assert loaded["ports"] == [80, 443]
    assert loaded["timeout"] == 15
    assert loaded["jump_host"] == "bastion.example.com"


def test_load_missing_profile_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    assert profiles.load_profile("nope") is None


def test_load_profile_fills_in_defaults(tmp_path, monkeypatch):
    d = tmp_path / "profiles"
    d.mkdir()
    (d / "bare.yaml").write_text("hosts:\n  - 1.2.3.4\n")
    monkeypatch.setattr(profiles, "PROFILES_DIR", d)

    loaded = profiles.load_profile("bare")
    assert loaded["hosts"] == ["1.2.3.4"]
    assert loaded["timeout"] == 10
    assert loaded["ports"] == []


def test_list_profiles_sorted(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    profiles.save_profile("zeta", hosts=["a"])
    profiles.save_profile("alpha", hosts=["b"])
    assert profiles.list_profiles() == ["alpha", "zeta"]


def test_list_profiles_empty_when_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "does-not-exist")
    assert profiles.list_profiles() == []


def test_delete_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    profiles.save_profile("temp", hosts=["a"])
    assert profiles.delete_profile("temp") is True
    assert profiles.load_profile("temp") is None
    assert profiles.delete_profile("temp") is False


def test_profile_file_permissions_are_owner_only(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    path = profiles.save_profile("secure", hosts=["a"])
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600
