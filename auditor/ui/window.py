"""Responsive, localized desktop UI for live local assessments."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QMainWindow, QMessageBox, QPushButton, QScrollArea, QSplitter,
    QStackedWidget, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout,
    QWidget,
)

from auditor.i18n import tr
from auditor.i18n.texts import LANGUAGES
from auditor.models import ScanResult
from auditor.reporting.export import export_html, export_json, export_pdf, localized_finding, report_html
from auditor.service import scan_live

STATUS_COLORS = {"PASS": "#00E5A0", "WARN": "#FFB020", "FAIL": "#FF4D6A", "UNKNOWN": "#4D7CFE", "NOT_APPLICABLE": "#8695A8"}
CATEGORIES = ("host", "ssh", "firewall", "accounts", "updates", "permissions")


class ScanWorker(QThread):
    result_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, scope: Path | None):
        super().__init__()
        self.scope = scope

    def run(self):
        try:
            self.result_ready.emit(scan_live(self.scope))
        except Exception as exc:  # worker boundary; error is displayed to user
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("shomatoff", "LinuxSecurityAuditor")
        self.language = self.settings.value("language", "en")
        if self.language not in LANGUAGES:
            self.language = "en"
        self.scope: Path | None = None
        self.result: ScanResult | None = None
        self.worker: ScanWorker | None = None
        self.current_page = 0
        self._build()
        self.apply_language()
        self.navigate(0)
        self.resize(1180, 760)
        self.setMinimumSize(820, 600)

    def t(self, key: str, **values) -> str:
        return tr(self.language, key, **values)

    def _label(self, bold=False):
        label = QLabel()
        label.setWordWrap(True)
        if bold:
            label.setProperty("heading", True)
        return label

    def _button(self, callback):
        button = QPushButton()
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(callback)
        return button

    def _page(self):
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)
        area.setWidget(inner)
        return area, layout

    def _build(self):
        self.setStyleSheet('''
            QMainWindow, QWidget { background: #0A0E14; color: #E7EFF7; font: 13px "DejaVu Sans"; }
            QLabel[heading="true"] { font-size: 22px; font-weight: 700; }
            QPushButton { background: #1A2633; border: 1px solid #34485B; border-radius: 9px; padding: 10px 14px; text-align: center; }
            QPushButton:hover { border-color: #00E5A0; background: #203548; }
            QPushButton:focus, QComboBox:focus, QTableWidget:focus { border: 2px solid #4D7CFE; }
            QPushButton[accent="true"] { background: #00C98D; color: #07140F; font-weight: 700; border: 0; }
            QPushButton:disabled { color: #687B8E; background: #17202B; }
            QComboBox, QTextBrowser, QTableWidget { background: #121821; border: 1px solid #2A394A; border-radius: 8px; padding: 5px; }
            QTableWidget { alternate-background-color: #1A2633; }
            QComboBox QAbstractItemView { background: #121821; color: #E7EFF7; }
            QHeaderView::section { background: #1A2633; color: #B9C9D8; padding: 8px; border: 0; }
            QTableWidget::item { padding: 6px; }
            QTableWidget::item:selected { background: #234760; }
            QScrollBar:vertical { background: #121821; width: 11px; }
            QScrollBar::handle:vertical { background: #466076; border-radius: 5px; }
        ''')
        root = QWidget()
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 14, 18, 14)
        top = QHBoxLayout()
        brand = QVBoxLayout()
        self.title = self._label(True)
        self.tagline = self._label()
        brand.addWidget(self.title)
        brand.addWidget(self.tagline)
        top.addLayout(brand, 1)
        self.language_label = self._label()
        top.addWidget(self.language_label)
        self.language_box = QComboBox()
        for code, name in LANGUAGES.items():
            self.language_box.addItem(name, code)
        self.language_box.setCurrentIndex(list(LANGUAGES).index(self.language))
        self.language_box.currentIndexChanged.connect(self._language_changed)
        top.addWidget(self.language_box)
        outer.addLayout(top)
        nav = QHBoxLayout()
        self.nav_buttons = []
        for index in range(5):
            button = self._button(lambda _=False, i=index: self.navigate(i))
            nav.addWidget(button)
            self.nav_buttons.append(button)
        outer.addLayout(nav)
        self.banner = self._label()
        self.banner.setStyleSheet("background:#122A30;color:#00E5A0;border-radius:8px;padding:11px;font-weight:700")
        outer.addWidget(self.banner)
        self.pages = QStackedWidget()
        self._build_dashboard()
        self._build_findings()
        self._build_categories()
        self._build_reports()
        self._build_settings()
        outer.addWidget(self.pages, 1)
        self.status_label = self._label()
        outer.addWidget(self.status_label)
        self.setCentralWidget(root)

    def _build_dashboard(self):
        page, layout = self._page()
        self.dashboard_title = self._label(True)
        self.dashboard_desc = self._label()
        layout.addWidget(self.dashboard_title)
        layout.addWidget(self.dashboard_desc)
        card_grid = QGridLayout()
        self.cards = {}
        for index, (key, color) in enumerate(STATUS_COLORS.items()):
            card = QFrame()
            card.setStyleSheet("QFrame { background:#121821; border:1px solid #263747; border-radius:12px; }")
            stack = QVBoxLayout(card)
            name = QLabel()
            name.setStyleSheet(f"border:0;color:{color};font-weight:700")
            value = QLabel("0")
            value.setStyleSheet("border:0;font-size:29px;font-weight:800")
            stack.addWidget(name)
            stack.addWidget(value)
            self.cards[key] = (name, value)
            card_grid.addWidget(card, index // 3, index % 3)
        layout.addLayout(card_grid)
        self.summary = self._label()
        layout.addWidget(self.summary)
        self.scope_state = self._label()
        layout.addWidget(self.scope_state)
        controls = QHBoxLayout()
        self.scan_button = self._button(self.start_scan)
        self.scan_button.setProperty("accent", True)
        self.choose_button = self._button(self.choose_scope)
        self.clear_button = self._button(self.clear_scope)
        for button in (self.scan_button, self.choose_button, self.clear_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.recent_title = self._label(True)
        self.recent_value = self._label()
        layout.addWidget(self.recent_title)
        layout.addWidget(self.recent_value)
        layout.addStretch()
        self.pages.addWidget(page)

    def _build_findings(self):
        page, layout = self._page()
        self.findings_title = self._label(True)
        self.findings_desc = self._label()
        layout.addWidget(self.findings_title)
        layout.addWidget(self.findings_desc)
        row = QHBoxLayout()
        self.filter_label = self._label()
        row.addWidget(self.filter_label)
        self.status_filter = QComboBox()
        self.status_filter.currentIndexChanged.connect(self.render_findings)
        row.addWidget(self.status_filter)
        self.category_filter = QComboBox()
        self.category_filter.currentIndexChanged.connect(self.render_findings)
        row.addWidget(self.category_filter)
        self.severity_filter = QComboBox()
        self.severity_filter.currentIndexChanged.connect(self.render_findings)
        row.addWidget(self.severity_filter)
        row.addStretch()
        layout.addLayout(row)
        splitter = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.table)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        splitter.addWidget(self.details)
        splitter.setSizes([350, 220])
        layout.addWidget(splitter, 1)
        self.pages.addWidget(page)

    def _build_categories(self):
        page, layout = self._page()
        self.categories_title = self._label(True)
        self.categories_desc = self._label()
        layout.addWidget(self.categories_title)
        layout.addWidget(self.categories_desc)
        grid = QGridLayout()
        self.category_buttons = {}
        for index, category in enumerate(CATEGORIES):
            button = self._button(lambda _=False, c=category: self.open_category(c))
            button.setMinimumHeight(84)
            grid.addWidget(button, index // 2, index % 2)
            self.category_buttons[category] = button
        layout.addLayout(grid)
        layout.addStretch()
        self.pages.addWidget(page)

    def _build_reports(self):
        page, layout = self._page()
        self.reports_title = self._label(True)
        self.reports_desc = self._label()
        layout.addWidget(self.reports_title)
        layout.addWidget(self.reports_desc)
        row = QHBoxLayout()
        self.export_buttons = {}
        for kind in ("html", "pdf", "json"):
            button = self._button(lambda _=False, k=kind: self.export(k))
            row.addWidget(button)
            self.export_buttons[kind] = button
        layout.addLayout(row)
        self.preview_title = self._label(True)
        layout.addWidget(self.preview_title)
        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(False)
        layout.addWidget(self.preview, 1)
        self.pages.addWidget(page)

    def _build_settings(self):
        page, layout = self._page()
        self.settings_title = self._label(True)
        self.settings_desc = self._label()
        self.privacy_checkbox = QCheckBox()
        self.privacy_checkbox.setChecked(self.settings.value("redact", True, type=bool))
        self.privacy_checkbox.stateChanged.connect(self._privacy_changed)
        self.method_title = self._label(True)
        self.method_desc = self._label()
        self.unknown_desc = self._label()
        self.remediation_desc = self._label()
        for widget in (self.settings_title, self.settings_desc, self.privacy_checkbox, self.method_title,
                       self.method_desc, self.unknown_desc, self.remediation_desc):
            layout.addWidget(widget)
        layout.addStretch()
        self.pages.addWidget(page)

    def apply_language(self):
        self.setWindowTitle(self.t("app.title"))
        self.title.setText(self.t("app.title"))
        self.tagline.setText(self.t("app.tagline"))
        self.language_label.setText(self.t("field.language"))
        for index, key in enumerate(("dashboard", "findings", "categories", "reports", "settings")):
            self.nav_buttons[index].setText(self.t("nav." + key))
        self.dashboard_title.setText(self.t("section.summary"))
        self.dashboard_desc.setText(self.t("description.dashboard"))
        for key, (label, _) in self.cards.items():
            label.setText(self.t("status." + key))
        self.scan_button.setText(self.t("action.scan"))
        self.choose_button.setText(self.t("action.choose_scope"))
        self.clear_button.setText(self.t("action.clear_scope"))
        self.recent_title.setText(self.t("section.recent"))
        self.findings_title.setText(self.t("section.findings"))
        self.findings_desc.setText(self.t("description.findings"))
        self.filter_label.setText(self.t("field.filter"))
        self.table.setHorizontalHeaderLabels([self.t("field.id"), self.t("field.status"), self.t("field.severity"),
                                              self.t("field.category"), self.t("field.title")])
        status_code = self.status_filter.currentData()
        category_code = self.category_filter.currentData()
        severity_code = self.severity_filter.currentData()
        self.status_filter.blockSignals(True)
        self.category_filter.blockSignals(True)
        self.severity_filter.blockSignals(True)
        self.status_filter.clear()
        self.status_filter.addItem(self.t("field.all"), None)
        for key in STATUS_COLORS:
            self.status_filter.addItem(self.t("status." + key), key)
        self.category_filter.clear()
        self.category_filter.addItem(self.t("field.all"), None)
        for key in CATEGORIES:
            self.category_filter.addItem(self.t("category." + key), key)
        self.severity_filter.clear()
        self.severity_filter.addItem(self.t("field.all"), None)
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.severity_filter.addItem(self.t("severity." + key), key)
        self.status_filter.setCurrentIndex(max(0, self.status_filter.findData(status_code)))
        self.category_filter.setCurrentIndex(max(0, self.category_filter.findData(category_code)))
        self.severity_filter.setCurrentIndex(max(0, self.severity_filter.findData(severity_code)))
        self.status_filter.blockSignals(False)
        self.category_filter.blockSignals(False)
        self.severity_filter.blockSignals(False)
        self.categories_title.setText(self.t("section.categories"))
        self.categories_desc.setText(self.t("description.categories"))
        self.reports_title.setText(self.t("section.reports"))
        self.reports_desc.setText(self.t("description.reports"))
        self.preview_title.setText(self.t("section.preview"))
        for kind, button in self.export_buttons.items():
            button.setText(self.t("action.export_" + kind))
        self.settings_title.setText(self.t("section.settings"))
        self.settings_desc.setText(self.t("description.settings"))
        self.privacy_checkbox.setText(self.t("field.privacy"))
        self.method_title.setText(self.t("section.about"))
        self.method_desc.setText(self.t("description.method"))
        self.unknown_desc.setText(self.t("description.unknown"))
        self.remediation_desc.setText(self.t("description.remediation"))
        self.render_result()
        self.status_label.setText(self.t("state.complete" if self.result else "state.idle"))

    def _language_changed(self):
        self.language = self.language_box.currentData()
        self.settings.setValue("language", self.language)
        self.apply_language()

    def _privacy_changed(self):
        self.settings.setValue("redact", self.privacy_checkbox.isChecked())
        self.render_preview()

    def navigate(self, page: int):
        self.current_page = page
        self.pages.setCurrentIndex(page)
        for index, button in enumerate(self.nav_buttons):
            button.setStyleSheet("border-color:#00E5A0;color:#00E5A0" if index == page else "")

    def choose_scope(self):
        path = QFileDialog.getExistingDirectory(self, self.t("dialog.choose_scope"))
        if path:
            self.scope = Path(path)
            self.scope_state.setText(self.t("state.scope_set"))

    def clear_scope(self):
        self.scope = None
        self.scope_state.setText(self.t("state.scope_none"))

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.status_label.setText(self.t("state.running"))
        self.scan_button.setEnabled(False)
        self.worker = ScanWorker(self.scope)
        self.worker.result_ready.connect(self._scan_ready)
        self.worker.failed.connect(self._scan_failed)
        self.worker.finished.connect(lambda: self.scan_button.setEnabled(True))
        self.worker.start()

    def _scan_ready(self, result: ScanResult):
        self.result = result
        self.status_label.setText(self.t("state.complete"))
        self.render_result()

    def _scan_failed(self, error: str):
        self.status_label.setText(self.t("state.error", error=error))

    def render_result(self):
        result = self.result
        self.banner.setText(self.t("banner.live") if result else self.t("state.idle"))
        counts = result.counts() if result else {key: 0 for key in STATUS_COLORS}
        for key, (_, value) in self.cards.items():
            value.setText(str(counts[key]))
        self.summary.setText(f"{self.t('metric.checked')}: {sum(counts.values())}   ·   {self.t('metric.coverage')}: {counts['PASS'] + counts['WARN'] + counts['FAIL']} / {sum(counts.values())}")
        self.scope_state.setText(self.t("state.scope_set" if self.scope else "state.scope_none"))
        self.recent_value.setText(f"{result.timestamp} UTC   ·   {result.os_name}" if result else self.t("field.not_scanned"))
        for category, button in self.category_buttons.items():
            number = sum(f.category == category for f in result.findings) if result else 0
            button.setText(f"{self.t('category.' + category)}   ·   {number}")
        self.render_findings()
        self.render_preview()

    def render_findings(self):
        if not hasattr(self, "table"):
            return
        self.table.setRowCount(0)
        if not self.result:
            self.details.setPlainText(self.t("field.not_scanned"))
            return
        findings = [f for f in self.result.findings if
                    (self.status_filter.currentData() is None or f.status == self.status_filter.currentData()) and
                    (self.category_filter.currentData() is None or f.category == self.category_filter.currentData()) and
                    (self.severity_filter.currentData() is None or f.severity == self.severity_filter.currentData())]
        self.table.setRowCount(len(findings))
        self.table.setSortingEnabled(False)
        for row, finding in enumerate(findings):
            localized = localized_finding(finding, self.language)
            values = [finding.rule_id, localized["status_label"], localized["severity_label"],
                      localized["category"], localized["title"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, finding.rule_id)
                if column == 1:
                    item.setForeground(QColor(STATUS_COLORS[finding.status]))
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.AscendingOrder)
        if findings:
            self.table.selectRow(0)
        else:
            self.details.setPlainText(self.t("field.none"))

    def show_details(self):
        if not self.result or not self.table.selectedItems():
            return
        rule_id = self.table.selectedItems()[0].data(Qt.UserRole)
        finding = next((item for item in self.result.findings if item.rule_id == rule_id), None)
        if not finding:
            return
        data = localized_finding(finding, self.language)
        lines = [f"{self.t('field.id')}: {rule_id} · {data['status_label']} · {data['severity_label']}",
                 f"{self.t('field.evidence')}: {data['evidence']}",
                 f"{self.t('field.impact')}: {data['impact']}",
                 f"{self.t('field.action')}: {data['manual_action']}",
                 f"{self.t('field.source')}: {data['source']}",
                 f"{self.t('field.limitation')}: {data['limitation']}"]
        self.details.setPlainText("\n\n".join(lines))

    def open_category(self, category: str):
        self.status_filter.setCurrentIndex(0)
        self.category_filter.setCurrentIndex(self.category_filter.findData(category))
        self.navigate(1)

    def render_preview(self):
        if not self.result:
            self.preview.setPlainText(self.t("field.not_scanned"))
        else:
            self.preview.setHtml(report_html(self.result, self.language, self.privacy_checkbox.isChecked()))
        for button in self.export_buttons.values():
            button.setEnabled(self.result is not None)

    def export(self, kind: str):
        if not self.result:
            QMessageBox.information(self, self.t("section.reports"), self.t("dialog.no_scan"))
            return
        path, _ = QFileDialog.getSaveFileName(self, self.t("dialog.export"),
                                              f"linux-security-audit.{kind}", f"{kind.upper()} (*.{kind})")
        if not path:
            return
        target = Path(path)
        if target.suffix.lower() != f".{kind}":
            target = target.with_suffix(f".{kind}")
        try:
            {"html": export_html, "pdf": export_pdf, "json": export_json}[kind](
                target, self.result, self.language, self.privacy_checkbox.isChecked())
        except (OSError, RuntimeError, ValueError) as exc:
            self.status_label.setText(self.t("state.export_error", error=str(exc)))
            return
        self.status_label.setText(self.t("state.exported", name=target.name))

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.wait(30000)
        super().closeEvent(event)
