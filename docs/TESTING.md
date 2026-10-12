# Testing and verification

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
QT_QPA_PLATFORM=offscreen .venv/bin/python main.py --smoke-test
./scripts/build_linux.sh
```

Automated tests use temporary directories and controlled evidence cases; published results are from a live host. They cover rule outcomes, absent/ambiguous SSH, firewall uncertainty, stale update metadata, allowlisted commands, timeout/missing command, Unicode names, symlink skip, permission failures, traversal bounds, translation completeness, live UI initialization/language switching, report redaction/HTML escaping, and PDF production. The screenshot script `QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/capture_live_screenshots.py` performs an actual local audit and captures the running QWidget. Do not publish its output without reviewing privacy first.

Local Ubuntu 24.04 verification on 2026-10-12: **42 pytest tests passed, 0 failed**, `ruff check .` passed, six live QWidget PNGs captured, and the PyInstaller Linux archive built. The packaged executable's `--smoke-test` initialized the UI and performed a real local scan. HTML, JSON and PDF were generated from that host in all three languages to an ignored private directory; `pdftotext` confirmed Cyrillic and Uzbek text. The archive checksum passed. Remote workflow results cannot be asserted before publication. CI is configured to run tests on Ubuntu 22.04/24.04, lint, build and smoke test the Linux artifact, and check its hash before a tag release.
