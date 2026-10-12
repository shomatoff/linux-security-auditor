# Security model

The application is intentionally read-only. It never invokes `sudo`, writes host configuration, changes permissions, opens private file contents, scans remote addresses, probes services over the network, or uploads results. The allowlist accepts only fixed command arguments; commands run with `shell=False`, bounded output and time. The optional directory walker uses metadata only and does not follow symlinks.

**Threat boundary:** the process has the current user's permissions. A selected directory may contain private names; the UI avoids listing individual paths, and exported reports hide the selected path by default. Filesystem metadata can change during a scan. This is a configuration review, not a malware detector or vulnerability scanner.

**Reporting:** HTML escapes dynamic fields and includes no scripts or external resources. PDF is rendered locally by Qt. JSON is UTF-8. Users should review exported files before sharing, especially if they disable redaction. Reports are saved only to a destination they choose.

**Dependencies:** pinned direct dependencies; PySide6 is the runtime package. CI uses pinned pytest, ruff and PyInstaller versions from `requirements-dev.txt`. Linux builds are unsigned. For security issues, use a private GitHub security advisory after the repository exists; do not post secrets in public issues.
