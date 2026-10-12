# Linux Security Auditor — English guide

[Main README](../README.md) · [Uzbek](README_UZ.md) · [Russian](README_RU.md)

Linux Security Auditor checks a small, documented set of local Linux configuration facts without changing them. The dashboard distinguishes confirmed results from unknown or inapplicable checks. The app supports Ubuntu 22.04/24.04 and Debian 12 as its initial rule validation scope.

## Start

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

Select **Scan this machine**. To check permissions, explicitly choose a directory; the app inspects metadata only, skips symlinks, and limits traversal. Open **Findings** for source, impact, limitation and manual guidance. **Categories** opens filtered findings. **Reports** previews and exports local HTML, PDF and JSON. **Settings / About** controls report path redaction and explains the method. The language selector is at the top and persists after restart.

## Evidence and interpretation

`PASS` means the documented rule passed with the available evidence; it does not mean the machine is secure. `WARN` and `FAIL` require human review. `UNKNOWN` means the tool lacked adequate evidence. `NOT_APPLICABLE` means the check did not apply, for example absent SSH. The tool never executes a suggested remediation. [Rules](RULE_CATALOG.md) · [Methodology](METHODOLOGY.md) · [Security](SECURITY.md).

## Screenshots and reports

[Live English dashboard](screenshots/dashboard-en.png) · [Live findings](screenshots/findings-live.png) · [Live report preview](screenshots/report-preview-live.png). These are real UI captures from a local Ubuntu 24.04 assessment. Live reports are intentionally not committed because they can reveal host information.

## Tests and limits

Run `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q` and `.venv/bin/python -m ruff check .`. See [testing](TESTING.md) and [platforms](PLATFORMS.md). This is a bounded configuration review, not a penetration test, CIS certification or assurance of full protection. Unprivileged firewall checks and stale package caches often yield inconclusive results.
