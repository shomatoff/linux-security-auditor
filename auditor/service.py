"""Single entry point for live local assessment."""
from __future__ import annotations

from pathlib import Path

from auditor.collectors.local import LocalCollector
from auditor.models import ScanResult
from auditor.rules.engine import evaluate


def scan_live(scope: Path | None = None) -> ScanResult:
    evidence = LocalCollector(scope).collect()
    os_item = next((item for item in evidence if item.key == "os.release"), None)
    os_name = "—"
    if os_item and os_item.state == "OK":
        os_name = f"{os_item.value['id']} {os_item.value['version']}"
    return ScanResult(evaluate(evidence), evidence, "LIVE", os_name, str(scope) if scope else "none")
