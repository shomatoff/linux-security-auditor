"""Deterministic rules, independent of host evidence collection."""
from __future__ import annotations

from auditor.models import Evidence, Finding

RULES = {
    "OS-001": ("host", "os.release"),
    "SSH-001": ("ssh", "ssh.service"),
    "SSH-002": ("ssh", "ssh.permitrootlogin"),
    "SSH-003": ("ssh", "ssh.passwordauthentication"),
    "SSH-004": ("ssh", "ssh.permitemptypasswords"),
    "SSH-005": ("ssh", "ssh.x11forwarding"),
    "SSH-006": ("ssh", "ssh.maxauthtries"),
    "FW-001": ("firewall", "firewall.effective"),
    "ACC-001": ("accounts", "accounts.extra_uid0"),
    "ACC-002": ("accounts", "accounts.admin_count"),
    "UPD-001": ("updates", "updates.pending"),
    "UPD-002": ("updates", "updates.automatic"),
    "PERM-001": ("permissions", "perms.world_writable"),
}


def _decision(rule: str, evidence: Evidence) -> tuple[str, str, str]:
    """Return status, severity and limitation translation key."""
    if evidence.state == "UNKNOWN":
        return "UNKNOWN", "INFO", "lim." + (evidence.note or "unknown")
    if evidence.state == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", "INFO", "lim." + (evidence.note or "none")
    value = evidence.value
    limitation = "lim." + evidence.note if evidence.note else "lim.none"
    if rule == "OS-001":
        supported = (value.get("id"), value.get("version")) in {
            ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12")
        }
        return ("PASS" if supported else "NOT_APPLICABLE", "INFO", limitation if supported else "lim.unsupported")
    if rule == "SSH-001":
        return "PASS", "INFO", limitation
    if rule == "SSH-002":
        if value == "no":
            return "PASS", "LOW", limitation
        if value in ("prohibit-password", "without-password", "forced-commands-only"):
            return "WARN", "MEDIUM", limitation
        return "FAIL", "HIGH", limitation
    if rule == "SSH-003":
        return ("PASS", "LOW", limitation) if value == "no" else ("WARN", "MEDIUM", limitation)
    if rule == "SSH-004":
        return ("PASS", "LOW", limitation) if value == "no" else ("FAIL", "HIGH", limitation)
    if rule == "SSH-005":
        return ("PASS", "LOW", limitation) if value == "no" else ("WARN", "LOW", limitation)
    if rule == "SSH-006":
        try:
            number = int(str(value))
        except ValueError:
            return "UNKNOWN", "INFO", "lim.unparseable"
        return ("PASS", "LOW", limitation) if 1 <= number <= 4 else ("WARN", "LOW", limitation)
    if rule == "FW-001":
        return {"active_deny": ("PASS", "LOW", limitation),
                "active_other": ("WARN", "MEDIUM", limitation),
                "inactive": ("FAIL", "HIGH", limitation)}.get(value, ("UNKNOWN", "INFO", "lim.unknown"))
    if rule == "ACC-001":
        return ("FAIL", "HIGH", limitation) if value > 0 else ("PASS", "LOW", limitation)
    if rule == "ACC-002":
        return "PASS", "INFO", "lim.inventory_only"
    if rule == "UPD-001":
        if value["count"] > 0:
            return "WARN", "MEDIUM", limitation
        if value["age_days"] > 7:
            return "UNKNOWN", "INFO", "lim.cache_stale"
        return "PASS", "LOW", "lim.cache_can_be_stale"
    if rule == "UPD-002":
        return ("PASS", "LOW", limitation) if value else ("WARN", "MEDIUM", limitation)
    if rule == "PERM-001":
        if value["writable"] > 0:
            return "FAIL", "MEDIUM", limitation
        if evidence.note in ("partial", "bounded"):
            return "UNKNOWN", "INFO", limitation
        return "PASS", "LOW", limitation
    raise ValueError(f"Unknown rule: {rule}")


def _display_value(evidence: Evidence) -> str:
    if evidence.state != "OK":
        return "—"
    value = evidence.value
    if evidence.key == "os.release":
        return f"{value['id']} {value['version']}"
    if evidence.key == "updates.pending":
        return f"{value['count']} / {value['age_days']}d"
    if evidence.key == "perms.world_writable":
        return f"{value['writable']} / {value['checked']}"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def evaluate(evidence: tuple[Evidence, ...]) -> tuple[Finding, ...]:
    index = {item.key: item for item in evidence}
    findings = []
    for rule_id, (category, evidence_key) in RULES.items():
        item = index.get(evidence_key, Evidence(evidence_key, "UNKNOWN", note="missing"))
        status, severity, limitation = _decision(rule_id, item)
        findings.append(Finding(
            rule_id=rule_id, category=category, status=status, severity=severity,
            title_key=f"rule.{rule_id}.title", evidence_key=f"rule.{rule_id}.evidence",
            evidence_value=_display_value(item), impact_key=f"rule.{rule_id}.impact",
            action_key=f"rule.{rule_id}.action", source=item.source or "—",
            limitation_key=limitation,
            confidence="HIGH" if item.state == "OK" and not item.note else "LIMITED",
        ))
    return tuple(findings)
