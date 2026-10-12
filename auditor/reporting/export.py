"""Offline, localized reporting from one ScanResult model."""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

from auditor.i18n import tr
from auditor.models import Finding, ScanResult

COLORS = {"PASS": "#00a878", "WARN": "#a76b00", "FAIL": "#bd2948", "UNKNOWN": "#4d7cfe", "NOT_APPLICABLE": "#637688"}


def localized_finding(item: Finding, language: str) -> dict:
    value = item.evidence_value
    if value in ("yes", "no"):
        value = tr(language, "field." + value)
    elif value in ("active_deny", "active_other", "inactive"):
        value = tr(language, "policy." + value)
    elif item.rule_id == "UPD-001" and value != "—":
        match = re.fullmatch(r"(\d+) / ([\d.]+)d", value)
        if match:
            value = f"{match.group(1)} / {match.group(2)} {tr(language, 'field.day')}"
    return {
        "rule_id": item.rule_id,
        "category": tr(language, "category." + item.category),
        "category_code": item.category,
        "status": item.status,
        "status_label": tr(language, "status." + item.status),
        "severity": item.severity,
        "severity_label": tr(language, "severity." + item.severity),
        "title": tr(language, item.title_key),
        "evidence": tr(language, item.evidence_key, value=value),
        "impact": tr(language, item.impact_key),
        "manual_action": tr(language, item.action_key),
        "source": item.source,
        "limitation": tr(language, item.limitation_key),
        "confidence": item.confidence,
    }


def report_payload(result: ScanResult, language: str, redact: bool = True) -> dict:
    scope = result.scope
    if scope != "none" and redact:
        scope = tr(language, "field.hidden")
    elif scope == "none":
        scope = tr(language, "field.none")
    counts = result.counts()
    known = counts["PASS"] + counts["WARN"] + counts["FAIL"]
    severity_counts = {level: sum(item.severity == level for item in result.findings)
                       for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    return {
        "application": tr(language, "app.title"),
        "mode": result.mode,
        "mode_label": tr(language, "report.live_warning"),
        "timestamp_utc": result.timestamp,
        "language": language,
        "operating_system": result.os_name,
        "directory_scope": scope,
        "redacted": redact,
        "counts": counts,
        "severity_counts": severity_counts,
        "known_checks": known,
        "unknown_checks": counts["UNKNOWN"],
        "methodology": tr(language, "description.method"),
        "disclaimer": tr(language, "report.disclaimer"),
        "findings": [localized_finding(item, language) for item in result.findings],
    }


def report_html(result: ScanResult, language: str, redact: bool = True) -> str:
    data = report_payload(result, language, redact)
    def e(value: object) -> str:
        return html.escape(str(value), quote=True)
    cards = "".join(
        f'<td class="card"><b>{e(tr(language, "status." + key))}: {number}</b></td>'
        for key, number in data["counts"].items()
    )
    rows = []
    for item in data["findings"]:
        color = COLORS[item["status"]]
        rows.append(
            f'<section class="finding"><p><span>{e(item["rule_id"])} · {e(item["category"])} · </span>'
            f'<strong style="color:{color}">{e(item["status_label"])}</strong></p>'
            f'<h2>{e(item["title"])}</h2>'
            f'<p><b>{e(tr(language, "field.evidence"))}:</b> {e(item["evidence"])}</p>'
            f'<p><b>{e(tr(language, "field.impact"))}:</b> {e(item["impact"])}</p>'
            f'<p><b>{e(tr(language, "field.action"))}:</b> {e(item["manual_action"])}</p>'
            f'<p class="muted">{e(tr(language, "field.source"))}: {e(item["source"])} · '
            f'{e(tr(language, "field.limitation"))}: {e(item["limitation"])}</p></section>'
        )
    return f'''<!doctype html>
<html lang="{e(language)}"><head><meta charset="utf-8"><title>{e(tr(language, "report.title"))}</title>
<style>
@page {{ size: A4; margin: 18mm; }}
body {{ font-family: "DejaVu Sans", "Noto Sans", sans-serif; background: #f4f7fa; color: #172333; margin: 0 auto; max-width: 900px; padding: 28px; line-height: 1.55; }}
h1 {{ font-size: 26px; margin: 0 0 7px; }} h2 {{ font-size: 17px; margin: 8px 0; }}
.banner {{ background: #0a2633; color: white; border-left: 6px solid #00a878; padding: 14px; margin: 17px 0; font-weight: bold; }}
.meta {{ color: #526575; }} .cards {{ width: 100%; margin: 17px 0; border-spacing: 5px; }}
.card {{ background: white; border: 1px solid #dae3ec; padding: 12px; }}
.card b {{ font-size: 13px; }}
.finding {{ background: white; border: 1px solid #dae3ec; border-radius: 10px; padding: 16px; margin: 12px 0; page-break-inside: avoid; }}
.finding p {{ margin: 5px 0; }} .muted {{ color: #526575; font-size: 12px; }}
footer {{ border-top: 1px solid #dae3ec; margin-top: 20px; padding-top: 12px; color: #526575; }}
</style></head><body>
<h1>{e(tr(language, "report.title"))}</h1>
<div class="banner">{e(data["mode_label"])}</div>
<p class="meta">{e(tr(language, "field.timestamp"))}: {e(data["timestamp_utc"])} · {e(tr(language, "field.os"))}: {e(data["operating_system"])}</p>
<p class="meta">{e(tr(language, "field.scope"))}: {e(data["directory_scope"])}</p>
<h2>{e(tr(language, "report.summary"))}</h2><table class="cards"><tr>{cards}</tr></table>
<p>{e(tr(language, "report.known"))}: {data["known_checks"]} · {e(tr(language, "report.unknown"))}: {data["unknown_checks"]}</p>
<h2>{e(tr(language, "report.findings"))}</h2>{''.join(rows)}
<footer><p>{e(data["methodology"])}</p><p>{e(data["disclaimer"])}</p><p>{e(tr(language, "report.reference"))}</p></footer>
</body></html>'''


def export_html(path: Path, result: ScanResult, language: str, redact: bool = True):
    Path(path).write_text(report_html(result, language, redact), encoding="utf-8")


def export_json(path: Path, result: ScanResult, language: str, redact: bool = True):
    Path(path).write_text(json.dumps(report_payload(result, language, redact), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def export_pdf(path: Path, result: ScanResult, language: str, redact: bool = True):
    """Qt renders Unicode with available system fonts; no third-party font is bundled."""
    from PySide6.QtGui import QPageSize, QTextDocument
    from PySide6.QtPrintSupport import QPrinter
    from PySide6.QtWidgets import QApplication

    application = QApplication.instance() or QApplication([])

    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(path))
    printer.setPageSize(QPageSize(QPageSize.A4))
    document = QTextDocument()
    document.setHtml(report_html(result, language, redact))
    document.print_(printer)
    del application
    if not Path(path).is_file() or Path(path).stat().st_size < 100:
        raise OSError("PDF writer did not produce a document")
