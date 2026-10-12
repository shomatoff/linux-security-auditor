from dataclasses import replace

import pytest

from tests.evidence_cases import evidence_case
from auditor.models import Evidence
from auditor.rules.engine import evaluate


def find(case, rule):
    return next(f for f in evaluate(evidence_case(case)) if f.rule_id == rule)


def test_stable_unique_rule_ids():
    ids = [f.rule_id for f in evaluate(evidence_case())]
    assert len(ids) == len(set(ids)) == 13


def test_secure_fixture_has_no_failures():
    assert all(f.status != "FAIL" for f in evaluate(evidence_case("secure")))


def test_unsafe_ssh_root_is_failure():
    assert find("insecure", "SSH-002").status == "FAIL"


def test_unsafe_empty_password_is_failure():
    assert find("insecure", "SSH-004").status == "FAIL"


def test_inactive_firewall_is_failure():
    assert find("insecure", "FW-001").status == "FAIL"


def test_extra_uid_zero_is_failure():
    assert find("insecure", "ACC-001").status == "FAIL"


def test_admin_inventory_is_not_failure():
    assert find("insecure", "ACC-002").status == "PASS"


def test_pending_updates_warning():
    assert find("mixed", "UPD-001").status == "WARN"


def test_partial_evidence_remains_unknown():
    assert find("partial", "FW-001").status == "UNKNOWN"
    assert find("partial", "SSH-002").status == "UNKNOWN"


def test_absent_ssh_is_not_failure():
    assert find("partial", "SSH-001").status == "NOT_APPLICABLE"


def test_unsupported_os_not_applicable():
    assert find("unsupported", "OS-001").status == "NOT_APPLICABLE"


def test_stale_cache_without_pending_is_unknown():
    evidence = tuple(replace(e, value={"count": 0, "age_days": 9.0}, note="cache_stale")
                     if e.key == "updates.pending" else e for e in evidence_case("secure"))
    assert next(f for f in evaluate(evidence) if f.rule_id == "UPD-001").status == "UNKNOWN"


def test_invalid_max_auth_tries_unknown():
    evidence = tuple(replace(e, value="garbage") if e.key == "ssh.maxauthtries" else e
                     for e in evidence_case())
    assert next(f for f in evaluate(evidence) if f.rule_id == "SSH-006").status == "UNKNOWN"


def test_missing_evidence_is_unknown():
    findings = evaluate((Evidence("os.release", "UNKNOWN", note="missing"),))
    assert all(f.status == "UNKNOWN" for f in findings)


def test_invalid_fixture_rejected():
    with pytest.raises(ValueError):
        evidence_case("secret")
