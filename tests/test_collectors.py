import time
from pathlib import Path

import pytest

from auditor.collectors import local


def test_os_release_parser():
    assert local.parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\n') == {"ID": "ubuntu", "VERSION_ID": "24.04"}


def test_sshd_parser_only_known_keys():
    assert local.parse_sshd_output("permitrootlogin no\npasswordauthentication yes\npassword x\n") == {
        "permitrootlogin": "no", "passwordauthentication": "yes"}


def test_ssh_fallback_rejects_include_and_match():
    assert local.fallback_ssh_config("Include /etc/ssh/sshd_config.d/*.conf") is None
    assert local.fallback_ssh_config("Match User test\nPermitRootLogin yes") is None


def test_ssh_fallback_only_explicit_values():
    assert local.fallback_ssh_config("# comment\nPermitRootLogin no\n") == {"permitrootlogin": "no"}


def test_allowlist_rejects_user_command():
    with pytest.raises(ValueError):
        local.run_allowed("bash", ("-c", "true"))


def test_missing_executable_is_unknown(monkeypatch):
    monkeypatch.setattr(local.shutil, "which", lambda _name: None)
    assert local.run_allowed("ufw", ("status", "verbose"))[2] is None


def test_subprocess_timeout(monkeypatch, tmp_path):
    command = tmp_path / "apt"
    command.write_text("#!/bin/sh\nsleep 2\n", encoding="utf-8")
    command.chmod(0o755)
    monkeypatch.setattr(local.shutil, "which", lambda _name: str(command))
    started = time.monotonic()
    assert local.run_allowed("apt", ("list", "--upgradable"), timeout=0.1)[1] == "timeout"
    assert time.monotonic() - started < 2


def test_firewall_command_error_unknown(monkeypatch):
    monkeypatch.setattr(local, "run_allowed", lambda *args, **kwargs: ("", "permission denied", 1))
    monkeypatch.setattr(local.shutil, "which", lambda _name: None)
    assert local.LocalCollector().firewall().state == "UNKNOWN"


def test_ufw_active_deny(monkeypatch):
    monkeypatch.setattr(local, "run_allowed", lambda *args, **kwargs: (
        "Status: active\nDefault: deny (incoming), allow (outgoing)\n", "", 0))
    assert local.LocalCollector().firewall().value == "active_deny"


def test_no_directory_not_scanned():
    assert local.LocalCollector().permissions().state == "NOT_APPLICABLE"


def test_invalid_directory_unknown(tmp_path):
    assert local.LocalCollector(tmp_path / "missing").permissions().state == "UNKNOWN"


def test_unicode_directory_and_read_only(tmp_path):
    folder = tmp_path / "o‘zbek Русский"
    folder.mkdir()
    sample = folder / "файл.txt"
    sample.write_text("secret contents", encoding="utf-8")
    before = sample.read_bytes()
    result = local.LocalCollector(folder).permissions()
    assert result.state == "OK" and result.value["checked"] == 2
    assert sample.read_bytes() == before


def test_symlink_skipped(tmp_path):
    folder = tmp_path / "scope"
    folder.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("x")
    (folder / "link").symlink_to(outside, target_is_directory=True)
    result = local.LocalCollector(folder).permissions()
    assert result.value["checked"] == 1


def test_symlink_scope_rejected(tmp_path):
    folder = tmp_path / "real"
    folder.mkdir()
    link = tmp_path / "link"
    link.symlink_to(folder, target_is_directory=True)
    assert local.LocalCollector(link).permissions().note == "invalid_scope"


def test_world_writable_detected(tmp_path):
    sample = tmp_path / "a"
    sample.write_text("x")
    sample.chmod(0o666)
    assert local.LocalCollector(tmp_path).permissions().value["writable"] >= 1


def test_bounded_traversal_is_limited(tmp_path):
    for index in range(8):
        (tmp_path / str(index)).write_text("x")
    result = local.LocalCollector(tmp_path, limit=3).permissions()
    assert result.value["limited"] and result.value["checked"] == 3


def test_permission_error_unknown(monkeypatch, tmp_path):
    original = local.os.scandir
    def denied(path):
        if Path(path) == tmp_path:
            raise PermissionError("denied")
        return original(path)
    monkeypatch.setattr(local.os, "scandir", denied)
    assert local.LocalCollector(tmp_path).permissions().state == "UNKNOWN"


def test_ssh_absent_nonfailure(monkeypatch):
    monkeypatch.setattr(local, "run_allowed", lambda *args, **kwargs: ("inactive", "", 3))
    monkeypatch.setattr(local.shutil, "which", lambda _name: None)
    monkeypatch.setattr(local.Path, "exists", lambda self: False)
    assert all(item.state == "NOT_APPLICABLE" for item in local.LocalCollector().ssh())
