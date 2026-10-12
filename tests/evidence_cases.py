"""Controlled evidence cases for deterministic rule unit tests."""
from auditor.models import Evidence


def evidence_case(case: str = "mixed") -> tuple[Evidence, ...]:
    if case not in ("mixed", "secure", "insecure", "partial", "unsupported"):
        raise ValueError("Unknown fixture")
    secure = case == "secure"
    insecure = case == "insecure"
    partial = case == "partial"
    return (
        Evidence("os.release", "OK", {"id": "other" if case == "unsupported" else "ubuntu", "version": "99" if case == "unsupported" else "24.04"}, "fixture"),
        Evidence("ssh.service", "NOT_APPLICABLE" if partial else "OK", None if partial else True, "fixture", "absent" if partial else ""),
        Evidence("ssh.permitrootlogin", "UNKNOWN" if partial else "OK", None if partial else "no" if secure else "yes", "fixture", "unavailable" if partial else ""),
        Evidence("ssh.passwordauthentication", "UNKNOWN" if partial else "OK", None if partial else "no" if secure else "yes", "fixture", "unavailable" if partial else ""),
        Evidence("ssh.permitemptypasswords", "UNKNOWN" if partial else "OK", None if partial else "no" if not insecure else "yes", "fixture", "unavailable" if partial else ""),
        Evidence("ssh.x11forwarding", "UNKNOWN" if partial else "OK", None if partial else "no" if secure else "yes", "fixture", "unavailable" if partial else ""),
        Evidence("ssh.maxauthtries", "UNKNOWN" if partial else "OK", None if partial else "3" if secure else "6", "fixture", "unavailable" if partial else ""),
        Evidence("firewall.effective", "UNKNOWN" if partial else "OK", None if partial else "active_deny" if secure else "inactive", "fixture", "permission_or_missing" if partial else ""),
        Evidence("accounts.extra_uid0", "OK", 1 if insecure else 0, "fixture"),
        Evidence("accounts.admin_count", "OK", 1, "fixture", "inventory_only"),
        Evidence("updates.pending", "UNKNOWN" if partial else "OK", None if partial else {"count": 0 if secure else 5, "age_days": 1.0}, "fixture", "cache_missing" if partial else "cache_can_be_stale"),
        Evidence("updates.automatic", "OK", secure, "fixture", "config_not_execution"),
        Evidence("perms.world_writable", "OK", {"writable": 0 if secure else 2, "checked": 24, "limited": False}, "fixture"),
    )
