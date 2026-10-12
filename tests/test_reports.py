import json
from dataclasses import replace

from auditor.i18n.texts import EN, RU, UZ
from auditor.reporting.export import export_html, export_json, export_pdf, report_html, report_payload
from auditor.service import scan_live


def test_translation_keys_equal():
    assert set(EN) == set(UZ) == set(RU)


def test_translation_values_nonempty():
    assert all(value.strip() for catalog in (EN, UZ, RU) for value in catalog.values())


def test_json_report_labels_live_and_is_local(tmp_path):
    target = tmp_path / "report.json"
    export_json(target, scan_live(), "uz")
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["mode"] == "LIVE"
    assert data["findings"] and "JONLI" in data["mode_label"]


def test_report_redacts_scope_by_default():
    result = replace(scan_live(), scope="/sensitive/secret-path")
    assert "secret-path" not in json.dumps(report_payload(result, "en"))
    assert "secret-path" in json.dumps(report_payload(result, "en", redact=False))


def test_html_escapes_evidence_and_scope():
    result = replace(scan_live(), scope='<img src=x onerror="bad">')
    html = report_html(result, "en", redact=False)
    assert '<img src=x onerror="bad">' not in html
    assert "&lt;img" in html
    assert "<script" not in html


def test_html_three_languages(tmp_path):
    for lang, phrase in (("en", "LIVE LOCAL AUDIT"), ("uz", "JONLI"), ("ru", "ЖИВАЯ")):
        path = tmp_path / f"{lang}.html"
        export_html(path, scan_live(), lang)
        assert phrase in path.read_text(encoding="utf-8")


def test_pdf_valid_and_unicode(tmp_path):
    path = tmp_path / "report.pdf"
    export_pdf(path, scan_live(), "ru")
    assert path.read_bytes().startswith(b"%PDF-")
    assert path.stat().st_size > 1000
