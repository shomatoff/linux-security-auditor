"""Capture genuine QWidget screenshots after a real, nonprivileged local audit."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["XDG_CONFIG_HOME"] = str(Path(__file__).resolve().parents[1] / ".local/config")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtWidgets import QApplication

from auditor.ui.window import MainWindow


def main():
    app = QApplication([])
    window = MainWindow()
    window.resize(1280, 800)
    window.show()
    window.start_scan()
    deadline = time.monotonic() + 25
    while window.result is None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)
    if window.result is None or window.result.mode != "LIVE":
        raise RuntimeError("Live scan did not finish; no screenshots captured")
    screenshots = Path(__file__).resolve().parents[1] / "docs/screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    for language in ("en", "uz", "ru"):
        window.language_box.setCurrentIndex(window.language_box.findData(language))
        window.navigate(0)
        app.processEvents()
        window.grab().save(str(screenshots / f"dashboard-{language}.png"))
    window.language_box.setCurrentIndex(window.language_box.findData("en"))
    window.navigate(1)
    app.processEvents()
    window.grab().save(str(screenshots / "findings-live.png"))
    window.navigate(3)
    app.processEvents()
    window.grab().save(str(screenshots / "report-preview-live.png"))
    window.navigate(4)
    app.processEvents()
    window.grab().save(str(screenshots / "settings-live.png"))
    window.close()
    print("Live scan:", window.result.counts(), "screenshots:", len(list(screenshots.glob("*.png"))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
