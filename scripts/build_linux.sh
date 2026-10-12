#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/pyinstaller --noconfirm --clean --onedir --name Linux-Security-Auditor main.py
QT_QPA_PLATFORM=offscreen dist/Linux-Security-Auditor/Linux-Security-Auditor --smoke-test
mkdir -p dist/packages
tar -C dist -czf dist/packages/Linux-Security-Auditor-Linux-x64.tar.gz Linux-Security-Auditor
sha256sum dist/packages/Linux-Security-Auditor-Linux-x64.tar.gz > dist/packages/SHA256SUMS
