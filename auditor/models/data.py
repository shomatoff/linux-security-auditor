"""Typed audit evidence and evaluated findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

EvidenceState = Literal["OK", "UNKNOWN", "NOT_APPLICABLE"]
Status = Literal["PASS", "WARN", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class Evidence:
    key: str
    state: EvidenceState
    value: object = None
    source: str = ""
    note: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    status: Status
    severity: Severity
    title_key: str
    evidence_key: str
    evidence_value: str
    impact_key: str
    action_key: str
    source: str
    limitation_key: str = "lim.none"
    confidence: str = "HIGH"


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    mode: Literal["LIVE"]
    os_name: str
    scope: str = "none"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def counts(self) -> dict[str, int]:
        keys = ("PASS", "WARN", "FAIL", "UNKNOWN", "NOT_APPLICABLE")
        return {key: sum(f.status == key for f in self.findings) for key in keys}
