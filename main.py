"""Desktop entry point; no audit starts until the user selects Scan."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from auditor.service import scan_live
from auditor.ui.window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setOrganizationName("shomatoff")
    app.setApplicationName("LinuxSecurityAuditor")
    window = MainWindow()
    window.show()
    if "--smoke-test" in sys.argv:
        app.processEvents()
        if len(scan_live().findings) != 13:
            return 1
        window.close()
        return 0
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
