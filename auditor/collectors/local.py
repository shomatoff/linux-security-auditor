"""Bounded, read-only collection from this Linux host."""
from __future__ import annotations

import os
import selectors
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

from auditor.models import Evidence

ALLOWED = {
    "systemctl": {("is-active", "ssh.service"), ("is-enabled", "unattended-upgrades.service")},
    "sshd": {("-T",)},
    "ufw": {("status", "verbose")},
    "firewall-cmd": {("--state",)},
    "apt": {("list", "--upgradable")},
}
SSH_KEYS = ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "x11forwarding", "maxauthtries")


def run_allowed(program: str, args: tuple[str, ...], timeout: float = 4) -> tuple[str, str, int | None]:
    """No shell, no user supplied arguments, bounded runtime and output."""
    if program not in ALLOWED or args not in ALLOWED[program]:
        raise ValueError("Command is not allowlisted")
    executable = shutil.which(program)
    if not executable and program == "sshd" and Path("/usr/sbin/sshd").exists():
        executable = "/usr/sbin/sshd"
    if not executable:
        return "", "missing", None
    try:
        process = subprocess.Popen([executable, *args], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return "", "unavailable", None
    chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": 262144, "stderr": 4096}
    deadline = time.monotonic() + min(timeout, 8)
    exceeded = False
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map() and time.monotonic() < deadline:
            for key, _ in selector.select(max(0, deadline - time.monotonic())):
                name = key.data
                data = os.read(key.fileobj.fileno(), min(8192, limits[name] - len(chunks[name]) + 1))
                if not data:
                    selector.unregister(key.fileobj)
                elif len(chunks[name]) + len(data) > limits[name]:
                    exceeded = True
                    break
                else:
                    chunks[name].extend(data)
            if exceeded:
                break
    timed_out = bool(selector.get_map()) and time.monotonic() >= deadline
    unfinished = process.poll() is None
    if exceeded or timed_out or unfinished:
        process.kill()
    process.wait(timeout=2)
    process.stdout.close()
    process.stderr.close()
    if exceeded:
        return "", "output_limit", None
    if timed_out or unfinished:
        return "", "timeout", None
    return chunks["stdout"].decode("utf-8", "replace"), chunks["stderr"].decode("utf-8", "replace"), process.returncode


def parse_os_release(data: str) -> dict[str, str]:
    values = {}
    for line in data.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def parse_sshd_output(data: str) -> dict[str, str]:
    output = {}
    for line in data.splitlines():
        key, _, value = line.partition(" ")
        if key in SSH_KEYS and value:
            output[key] = value.strip().lower()
    return output


def fallback_ssh_config(config: str) -> dict[str, str] | None:
    """Only explicit, unconditional settings; Include/Match makes it inconclusive."""
    output = {}
    for line in config.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        key = key.lower()
        if key in ("include", "match"):
            return None
        if key in SSH_KEYS and key not in output:
            output[key] = value.strip().lower()
    return output


class LocalCollector:
    def __init__(self, scope: Path | None = None, limit: int = 250, depth: int = 2):
        self.scope = scope
        self.limit = max(1, min(limit, 1000))
        self.depth = max(0, min(depth, 4))

    def collect(self) -> tuple[Evidence, ...]:
        return tuple(
            [self.os_release(), *self.ssh(), self.firewall(), *self.accounts(),
             self.updates(), self.automatic_updates(), self.permissions()]
        )

    def os_release(self) -> Evidence:
        try:
            values = parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
        except OSError:
            return Evidence("os.release", "UNKNOWN", source="/etc/os-release", note="unreadable")
        system, version = values.get("ID", ""), values.get("VERSION_ID", "")
        if not system or not version:
            return Evidence("os.release", "UNKNOWN", source="/etc/os-release", note="missing")
        return Evidence("os.release", "OK", {"id": system, "version": version}, source="/etc/os-release")

    def ssh(self) -> list[Evidence]:
        prefix = "ssh."
        service, _, service_rc = run_allowed("systemctl", ("is-active", "ssh.service"))
        sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
        keys = [prefix + key for key in SSH_KEYS]
        if not sshd and service != "active":
            return [Evidence("ssh.service", "NOT_APPLICABLE", False, "systemctl", "absent"), *
                    [Evidence(key, "NOT_APPLICABLE", source="sshd -T", note="absent") for key in keys]]
        if service_rc is None:
            service_e = Evidence("ssh.service", "UNKNOWN", source="systemctl is-active ssh.service", note="unavailable")
        else:
            service_e = Evidence("ssh.service", "OK", service == "active", "systemctl is-active ssh.service")
        if service_e.state == "OK" and not service_e.value:
            return [service_e, *[Evidence(key, "NOT_APPLICABLE", source="sshd -T", note="inactive") for key in keys]]
        config_path = Path("/etc/ssh/sshd_config")
        try:
            config = config_path.read_text(encoding="utf-8")
        except OSError:
            config = ""
        # An Include can introduce a Match block or override a global value.
        # Without a client context we cannot turn sshd -T into a universal policy claim.
        context_dependent = bool(re.search(r"^\s*(?:Match|Include)\s", config, re.I | re.M))
        text, _, rc = run_allowed("sshd", ("-T",))
        if rc == 0 and not context_dependent:
            values = parse_sshd_output(text)
            source = "sshd -T"
        elif config and not context_dependent:
            values = fallback_ssh_config(config) or {}
            source = "/etc/ssh/sshd_config"
        else:
            values, source = {}, "/etc/ssh/sshd_config"
        evidence = [service_e]
        for key in SSH_KEYS:
            value = values.get(key)
            evidence.append(Evidence(prefix + key, "OK" if value is not None else "UNKNOWN", value, source,
                                     "match_context" if context_dependent else "effective_unavailable" if value is None else ""))
        return evidence

    def firewall(self) -> Evidence:
        output, error, rc = run_allowed("ufw", ("status", "verbose"))
        if rc == 0 and re.search(r"^Status:\s+active", output, re.I | re.M):
            default = re.search(r"^Default:\s+(.+)$", output, re.M)
            if default and re.search(r"deny\s*\(incoming\)", default.group(1), re.I):
                return Evidence("firewall.effective", "OK", "active_deny", "ufw status verbose")
            return Evidence("firewall.effective", "OK", "active_other", "ufw status verbose")
        if rc == 0 and re.search(r"^Status:\s+inactive", output, re.I | re.M):
            return Evidence("firewall.effective", "OK", "inactive", "ufw status verbose")
        if shutil.which("firewall-cmd"):
            state, _, state_rc = run_allowed("firewall-cmd", ("--state",))
            if state_rc == 0 and state == "running":
                return Evidence("firewall.effective", "UNKNOWN", source="firewall-cmd --state", note="policy_not_visible")
        return Evidence("firewall.effective", "UNKNOWN", source="ufw status verbose", note="permission_or_missing" if error or rc is None else "policy_not_visible")

    def accounts(self) -> tuple[Evidence, Evidence]:
        try:
            passwd = Path("/etc/passwd").read_text(encoding="utf-8")
            groups = Path("/etc/group").read_text(encoding="utf-8")
        except OSError:
            return (Evidence("accounts.extra_uid0", "UNKNOWN", source="/etc/passwd", note="unreadable"),
                    Evidence("accounts.admin_count", "UNKNOWN", source="/etc/group", note="unreadable"))
        extra = 0
        for line in passwd.splitlines():
            fields = line.split(":")
            if len(fields) >= 4 and fields[2] == "0" and fields[0] != "root":
                extra += 1
        admins = set()
        for line in groups.splitlines():
            fields = line.split(":")
            if len(fields) >= 4 and fields[0] in ("sudo", "wheel"):
                admins.update(member for member in fields[3].split(",") if member)
        return (Evidence("accounts.extra_uid0", "OK", extra, "/etc/passwd"),
                Evidence("accounts.admin_count", "OK", len(admins), "/etc/group", "inventory_only"))

    def updates(self) -> Evidence:
        if not shutil.which("apt"):
            return Evidence("updates.pending", "NOT_APPLICABLE", source="apt", note="unsupported")
        lists = list(Path("/var/lib/apt/lists").glob("*_Packages*"))
        if not lists:
            return Evidence("updates.pending", "UNKNOWN", source="apt", note="cache_missing")
        try:
            age_days = (time.time() - max(path.stat().st_mtime for path in lists)) / 86400
        except OSError:
            return Evidence("updates.pending", "UNKNOWN", source="apt", note="unreadable")
        output, _, rc = run_allowed("apt", ("list", "--upgradable"), timeout=8)
        if rc != 0:
            return Evidence("updates.pending", "UNKNOWN", source="apt list --upgradable", note="command_failed")
        count = sum("[upgradable from:" in line for line in output.splitlines())
        return Evidence("updates.pending", "OK", {"count": count, "age_days": round(age_days, 1)},
                        "apt list --upgradable", "cache_stale" if age_days > 7 else "cache_can_be_stale")

    def automatic_updates(self) -> Evidence:
        path = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        try:
            config = path.read_text(encoding="utf-8")
        except OSError:
            return Evidence("updates.automatic", "UNKNOWN", source=str(path), note="unreadable")
        enabled = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', config))
        return Evidence("updates.automatic", "OK", enabled, source=str(path), note="config_not_execution")

    def permissions(self) -> Evidence:
        if self.scope is None:
            return Evidence("perms.world_writable", "NOT_APPLICABLE", source="lstat/scandir", note="not_selected")
        path = Path(self.scope)
        try:
            root_stat = path.lstat()
            if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
                return Evidence("perms.world_writable", "UNKNOWN", source="lstat/scandir", note="invalid_scope")
        except OSError:
            return Evidence("perms.world_writable", "UNKNOWN", source="lstat/scandir", note="invalid_scope")
        pending = [(path, 0)]
        visited = 1
        writable = int(bool(root_stat.st_mode & stat.S_IWOTH))
        errors = 0
        while pending and visited < self.limit:
            current, level = pending.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if visited >= self.limit:
                            break
                        try:
                            item = entry.stat(follow_symlinks=False)
                        except OSError:
                            errors += 1
                            continue
                        if stat.S_ISLNK(item.st_mode):
                            continue
                        visited += 1
                        if item.st_mode & stat.S_IWOTH:
                            writable += 1
                        if stat.S_ISDIR(item.st_mode) and level < self.depth:
                            pending.append((Path(entry.path), level + 1))
            except OSError:
                errors += 1
        limited = bool(pending) or visited >= self.limit
        note = "partial" if errors else "bounded" if limited else ""
        return Evidence("perms.world_writable", "OK" if writable > 0 or not errors else "UNKNOWN",
                        {"writable": writable, "checked": visited, "limited": limited},
                        "lstat/scandir", note)
