import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from auditor.ui.window import MainWindow
from auditor.service import scan_live


def test_ui_pages_and_language_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.pages.count() == 5
    window._scan_ready(scan_live())
    original = window.result
    window.language_box.setCurrentIndex(window.language_box.findData("uz"))
    assert window.result is original
    assert window.nav_buttons[0].text() == "Bosh sahifa"
    window.language_box.setCurrentIndex(window.language_box.findData("ru"))
    assert window.nav_buttons[0].text() == "Панель"
    window.open_category("ssh")
    assert window.pages.currentIndex() == 1
    assert window.category_filter.currentData() == "ssh"
    window.close()
    reopened = MainWindow()
    assert reopened.language == "ru"
    reopened.close()
    app.processEvents()
