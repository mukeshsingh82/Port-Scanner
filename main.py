#!/usr/bin/env python3
"""
main.py - PySide6 desktop GUI for Mini Port Scanner.

All networking lives in scanner.py. This module only handles the window,
the background worker thread and exporting results.
"""

from __future__ import annotations

import bisect
import csv
import re
import sys
import threading
import time
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor, QFont, QKeySequence, QPalette, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractSpinBox,
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import scanner

APP_TITLE = "Mini Port Scanner"
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1000
READY_MESSAGE = "Ready. Enter a target and press Start Scan (Ctrl+Enter)."
FOOTER_TEXT = "For authorized security testing and defensive use only."

COLOR_TEXT = "#dbe4f0"
COLOR_ACCENT = "#22d3ee"
COLOR_OK = "#34d399"
COLOR_WARN = "#fbbf24"
COLOR_ERROR = "#f87171"

STYLESHEET = """
QMainWindow, QDialog { background-color: #0b1220; }
QWidget#central { background-color: #0b1220; }
QLabel { background: transparent; color: #dbe4f0; }
QLabel#title { font-size: 22px; font-weight: 700; color: #f8fafc; }
QLabel#subtitle { color: #7c8ba1; }
QLabel#cardTitle { font-size: 11px; font-weight: 700; color: #22d3ee; }
QLabel#fieldLabel { font-size: 12px; color: #7c8ba1; }
QLabel#summaryKey { color: #7c8ba1; }
QLabel#summaryValue { font-weight: 600; }
QLabel#footer { color: #5b6b82; font-size: 11px; }
QFrame#card { background-color: #111b2e; border: 1px solid #1f2d45; border-radius: 8px; }
QLineEdit, QSpinBox {
    background-color: #0b1220; color: #f1f5f9; border: 1px solid #263650; border-radius: 6px;
    padding: 6px 10px; selection-background-color: #22d3ee; selection-color: #06121a;
}
QLineEdit:focus, QSpinBox:focus { border: 1px solid #22d3ee; }
QLineEdit:disabled, QSpinBox:disabled { color: #56657a; border-color: #1f2d45; }
QPushButton {
    background-color: #1a2740; color: #e2e8f0; border: 1px solid #2b3d5c; border-radius: 6px;
    padding: 7px 18px; font-weight: 600;
}
QPushButton:hover { background-color: #22324f; }
QPushButton:pressed { background-color: #142036; }
QPushButton:disabled { background-color: #131d30; color: #56657a; border-color: #1f2d45; }
QPushButton#primary { background-color: #22d3ee; color: #06121a; border: 1px solid #22d3ee; }
QPushButton#primary:hover { background-color: #67e8f9; border-color: #67e8f9; }
QPushButton#primary:pressed { background-color: #06b6d4; }
QPushButton#primary:disabled { background-color: #164e5a; color: #0b1220; border-color: #164e5a; }
QPushButton#danger { background-color: #3b1219; color: #fecaca; border: 1px solid #7f1d1d; }
QPushButton#danger:hover { background-color: #4c1620; }
QPushButton#danger:disabled { background-color: #1c1420; color: #5a4650; border-color: #2a1d26; }
QProgressBar {
    background-color: #0b1220; border: 1px solid #263650; border-radius: 6px;
    min-height: 14px; max-height: 14px;
}
QProgressBar::chunk { background-color: #22d3ee; border-radius: 5px; }
QTableWidget {
    background-color: #0b1220; alternate-background-color: #0e182a; color: #e2e8f0;
    border: 1px solid #1f2d45; border-radius: 6px;
    selection-background-color: #163a4a; selection-color: #f8fafc;
}
QTableWidget::item { padding: 4px; }
QHeaderView::section {
    background-color: #111b2e; color: #7dd3fc; padding: 6px; border: none;
    border-bottom: 1px solid #263650; font-weight: 600;
}
QTableCornerButton::section { background-color: #111b2e; border: none; }
QScrollBar:vertical { background: #0b1220; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #263650; border-radius: 4px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip { background-color: #1a2740; color: #e2e8f0; border: 1px solid #2b3d5c; }
"""


def dark_palette() -> QPalette:
    """Dark Fusion palette so any widget not covered by the stylesheet still looks right."""
    base = QColor("#0b1220")
    surface = QColor("#111b2e")
    text = QColor(COLOR_TEXT)
    disabled = QColor("#56657a")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, base)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, surface)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, surface)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.ToolTipBase, surface)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#06121a"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#5b6b82"))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, disabled)
    return palette


class ScanWorker(QThread):
    """Runs one scan in the background and reports back through signals."""

    resolved = Signal(str)                  # numeric IP being scanned
    port_found = Signal(int, str)           # open port, service name
    progress = Signal(int, int)             # ports scanned so far, total ports
    failed = Signal(str)                    # fatal error message
    completed = Signal(bool, int, int, str)  # stopped by user?, filtered, errors, last error

    def __init__(self, host: str, start_port: int, end_port: int, parent=None) -> None:
        super().__init__(parent)
        self._host = host
        self._start_port = start_port
        self._end_port = end_port
        self._total = end_port - start_port + 1
        self._stop_event = threading.Event()
        self._scanned = 0
        self._filtered = 0
        self._errors = 0
        self._last_error = ""
        self._last_progress_emit = 0.0

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        try:
            target = scanner.resolve_target(self._host)
            self.resolved.emit(target.ip)
            scanner.scan_ports(target, self._start_port, self._end_port, self._on_result, self._stop_event)
        except scanner.ScanError as exc:
            self.progress.emit(self._scanned, self._total)
            self.failed.emit(str(exc))
            return
        except Exception as exc:  # safety net: a bug must never take the GUI down
            self.progress.emit(self._scanned, self._total)
            self.failed.emit(f"Unexpected error: {exc}")
            return
        self.progress.emit(self._scanned, self._total)
        self.completed.emit(self._stop_event.is_set(), self._filtered, self._errors, self._last_error)

    def _on_result(self, result: scanner.PortResult) -> None:
        """Called from the scanning thread for every probed port."""
        self._scanned += 1
        if result.state == scanner.STATE_OPEN:
            self.port_found.emit(result.port, result.service)
        elif result.state == scanner.STATE_FILTERED:
            self._filtered += 1
        elif result.state == scanner.STATE_ERROR:
            self._errors += 1
            self._last_error = result.detail

        now = time.monotonic()
        if now - self._last_progress_emit >= 0.05:  # ~20 UI updates per second is plenty
            self._last_progress_emit = now
            self.progress.emit(self._scanned, self._total)


def write_csv(path: str, rows: list[tuple[int, str, str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Port", "State", "Service"])
        writer.writerows(rows)


def write_txt(path: str, rows: list[tuple[int, str, str]], summary: dict[str, str]) -> None:
    width = max(len(key) for key in summary) + 1
    lines = [f"{APP_TITLE} - Scan Report", f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}", ""]
    lines += [f"{key + ':':<{width}} {value}" for key, value in summary.items()]
    lines += ["", f"{'PORT':<8}{'STATE':<10}SERVICE"]
    lines += [f"{port:<8}{state:<10}{service}" for port, state, service in rows] or ["(no open ports found)"]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(780, 720)

        self._worker: ScanWorker | None = None
        self._open_ports: list[int] = []       # sorted, mirrors the table rows
        self._services: dict[int, str] = {}
        self._total = 0
        self._scanned = 0
        self._scan_started = 0.0
        self._has_report = False               # a scan has finished, so export makes sense

        self._build_ui()
        self._setup_shortcuts()
        self._update_progress(0, 0)
        self._update_open_count()
        self.summary_status.setText("Idle")
        self._set_running(False)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 18, 20, 12)
        root.setSpacing(12)

        # Header
        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel(APP_TITLE)
        title.setObjectName("title")
        subtitle = QLabel("Lightweight TCP connect scanner for hosts you are authorized to test")
        subtitle.setObjectName("subtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles)
        header.addStretch()
        badge = QLabel("TCP CONNECT  ·  PYSIDE6")
        badge.setObjectName("cardTitle")
        header.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header)

        # Target & port range
        card, layout = self._make_card("Target & Port Range")
        fields = QHBoxLayout()
        fields.setSpacing(12)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("127.0.0.1, localhost, or ::1")
        self.start_port = self._make_port_spin(DEFAULT_START_PORT)
        self.end_port = self._make_port_spin(DEFAULT_END_PORT)
        fields.addLayout(self._labeled("Target (IP address or hostname)", self.target_input), 3)
        fields.addLayout(self._labeled("Start Port", self.start_port), 1)
        fields.addLayout(self._labeled("End Port", self.end_port), 1)
        layout.addLayout(fields)
        root.addWidget(card)

        # Scan controls
        controls = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("primary")
        self.start_button.setToolTip("Start scanning (Ctrl+Enter)")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setObjectName("danger")
        self.stop_button.setToolTip("Stop the running scan (Esc)")
        self.stop_button.clicked.connect(self.stop_scan)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addStretch()
        hint = QLabel("Ctrl+Enter start   ·   Esc stop   ·   Ctrl+L clear")
        hint.setObjectName("fieldLabel")
        controls.addWidget(hint)
        root.addLayout(controls)

        # Progress
        card, layout = self._make_card("Progress")
        counters = QHBoxLayout()
        self.scanned_label = QLabel()
        self.open_label = QLabel()
        self.open_label.setStyleSheet(f"color: {COLOR_OK}; font-weight: 600;")
        counters.addWidget(self.scanned_label)
        counters.addStretch()
        counters.addWidget(self.open_label)
        layout.addLayout(counters)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel(READY_MESSAGE)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        root.addWidget(card)

        # Results table (open ports only)
        card, layout = self._make_card("Open Ports")
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Port", "State", "Service"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header_view.setHighlightSections(False)
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 110)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.StyleHint.TypeWriter)
        self.table.setFont(mono)
        layout.addWidget(self.table)
        root.addWidget(card, 1)

        # Summary
        card, layout = self._make_card("Scan Summary")
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(6)
        self.summary_target = self._summary_value(grid, 0, 0, "Target")
        self.summary_range = self._summary_value(grid, 0, 2, "Port range")
        self.summary_scanned = self._summary_value(grid, 1, 0, "Total ports scanned")
        self.summary_open = self._summary_value(grid, 1, 2, "Open ports")
        self.summary_status = self._summary_value(grid, 2, 0, "Scan status")
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        layout.addLayout(grid)
        root.addWidget(card)

        # Export / clear
        actions = QHBoxLayout()
        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(lambda *_: self._export("csv"))
        self.export_txt_button = QPushButton("Export TXT")
        self.export_txt_button.clicked.connect(lambda *_: self._export("txt"))
        self.clear_button = QPushButton("Clear")
        self.clear_button.setToolTip("Reset results and inputs (Ctrl+L)")
        self.clear_button.clicked.connect(self.clear_all)
        actions.addWidget(self.export_csv_button)
        actions.addWidget(self.export_txt_button)
        actions.addStretch()
        actions.addWidget(self.clear_button)
        root.addLayout(actions)

        footer = QLabel(FOOTER_TEXT)
        footer.setObjectName("footer")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(footer)

    @staticmethod
    def _make_card(title: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 14)
        layout.setSpacing(10)
        heading = QLabel(title.upper())
        heading.setObjectName("cardTitle")
        layout.addWidget(heading)
        return card, layout

    @staticmethod
    def _labeled(text: str, widget: QWidget) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(4)
        label = QLabel(text)
        label.setObjectName("fieldLabel")
        box.addWidget(label)
        box.addWidget(widget)
        return box

    @staticmethod
    def _make_port_spin(value: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(scanner.MIN_PORT, scanner.MAX_PORT)
        spin.setValue(value)
        spin.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return spin

    @staticmethod
    def _summary_value(grid: QGridLayout, row: int, column: int, key: str) -> QLabel:
        key_label = QLabel(f"{key}:")
        key_label.setObjectName("summaryKey")
        value_label = QLabel("—")
        value_label.setObjectName("summaryValue")
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        grid.addWidget(key_label, row, column)
        grid.addWidget(value_label, row, column + 1)
        return value_label

    def _setup_shortcuts(self) -> None:
        for sequence in ("Ctrl+Return", "Ctrl+Enter"):
            QShortcut(QKeySequence(sequence), self).activated.connect(self.start_scan)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self).activated.connect(self.stop_scan)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self.clear_all)

    # ---------------------------------------------------------- scan control
    @Slot()
    def start_scan(self) -> None:
        if self._worker is not None:
            return
        try:
            host = scanner.validate_target(self.target_input.text())
            start_port, end_port = scanner.validate_port_range(self.start_port.value(), self.end_port.value())
        except scanner.ScanError as exc:
            QMessageBox.warning(self, "Invalid input", str(exc))
            return

        self.target_input.setText(host)
        self._reset_results()
        self._total = end_port - start_port + 1
        self._scan_started = time.monotonic()
        self._update_progress(0, self._total)
        self.summary_target.setText(host)
        self.summary_range.setText(f"{start_port} - {end_port}")
        self.summary_status.setText("Scanning")
        self._set_status(f"Resolving {host}…", COLOR_ACCENT)

        self._worker = ScanWorker(host, start_port, end_port, self)
        self._worker.resolved.connect(self._on_resolved)
        self._worker.port_found.connect(self._on_port_found)
        self._worker.progress.connect(self._on_progress)
        self._worker.completed.connect(self._on_completed)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._set_running(True)
        self._worker.start()

    @Slot()
    def stop_scan(self) -> None:
        if self._worker is None:
            return
        self._worker.stop()
        self.stop_button.setEnabled(False)
        self._set_status("Stopping scan…", COLOR_WARN)

    @Slot()
    def clear_all(self) -> None:
        if self._worker is not None:
            return
        self._reset_results()
        self._total = 0
        self._has_report = False
        self.target_input.clear()
        self.start_port.setValue(DEFAULT_START_PORT)
        self.end_port.setValue(DEFAULT_END_PORT)
        self.summary_target.setText("—")
        self.summary_range.setText("—")
        self.summary_status.setText("Idle")
        self._update_progress(0, 0)
        self._set_status(READY_MESSAGE)
        self._set_running(False)
        self.target_input.setFocus()

    # ------------------------------------------------------- worker callbacks
    @Slot(str)
    def _on_resolved(self, ip: str) -> None:
        host = self.summary_target.text()
        if ip != host:
            self.summary_target.setText(f"{host} ({ip})")
        self._set_status(f"Scanning {ip}, ports {self.summary_range.text()}…", COLOR_ACCENT)

    @Slot(int, str)
    def _on_port_found(self, port: int, service: str) -> None:
        index = bisect.bisect_left(self._open_ports, port)
        self._open_ports.insert(index, port)
        self._services[port] = service

        port_item = QTableWidgetItem(str(port))
        state_item = QTableWidgetItem(scanner.STATE_OPEN)
        service_item = QTableWidgetItem(service)
        bold = QFont(self.table.font())
        bold.setBold(True)
        state_item.setFont(bold)
        state_item.setForeground(QColor(COLOR_OK))
        port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        state_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self.table.insertRow(index)
        for column, item in enumerate((port_item, state_item, service_item)):
            self.table.setItem(index, column, item)
        self._update_open_count()

    @Slot(int, int)
    def _on_progress(self, scanned: int, total: int) -> None:
        self._update_progress(scanned, total)

    @Slot(bool, int, int, str)
    def _on_completed(self, stopped: bool, filtered: int, errors: int, last_error: str) -> None:
        elapsed = time.monotonic() - self._scan_started
        open_count = len(self._open_ports)
        if stopped:
            status, color = "Stopped", COLOR_WARN
            message = (f"Scan stopped after {self._scanned} of {self._total} ports — "
                       f"{open_count} open ({elapsed:.1f}s).")
        else:
            status, color = "Completed", COLOR_OK
            message = f"Scan completed — {self._scanned} ports checked, {open_count} open ({elapsed:.1f}s)."
            if self._scanned and filtered == self._scanned:
                color = COLOR_WARN
                message += " Every connection timed out: the host may be down or firewalled."
        if errors:
            status, color = f"{status} with errors", COLOR_WARN
            message += f" {errors} port(s) could not be checked (last error: {last_error})."

        self.summary_status.setText(status)
        self._set_status(message, color)
        self._has_report = True

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self.summary_status.setText("Error")
        self._set_status(message, COLOR_ERROR)
        self._has_report = True
        QMessageBox.critical(self, "Scan failed", message)

    @Slot()
    def _on_worker_finished(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._set_running(False)

    # ---------------------------------------------------------------- export
    def _export(self, extension: str) -> None:
        host = self.summary_target.text().split(" ")[0]
        safe_host = re.sub(r"[^A-Za-z0-9.-]+", "_", host).strip("_") or "scan"
        suggested = f"portscan_{safe_host}_{self.summary_range.text().replace(' ', '')}.{extension}"
        name_filter = "CSV files (*.csv)" if extension == "csv" else "Text files (*.txt)"
        path, _ = QFileDialog.getSaveFileName(self, "Export scan results", suggested, name_filter)
        if not path:
            return
        if not path.lower().endswith(f".{extension}"):
            path += f".{extension}"

        rows = [(port, scanner.STATE_OPEN, self._services[port]) for port in self._open_ports]
        try:
            if extension == "csv":
                write_csv(path, rows)
            else:
                write_txt(path, rows, self._summary())
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write {path}:\n{exc}")
            return
        self._set_status(f"Results exported to {path}", COLOR_OK)

    def _summary(self) -> dict[str, str]:
        return {
            "Target": self.summary_target.text(),
            "Port range": self.summary_range.text(),
            "Total ports scanned": self.summary_scanned.text(),
            "Open ports": self.summary_open.text(),
            "Scan status": self.summary_status.text(),
        }

    # --------------------------------------------------------------- helpers
    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.clear_button.setEnabled(not running)
        for widget in (self.target_input, self.start_port, self.end_port):
            widget.setEnabled(not running)
        can_export = not running and self._has_report
        self.export_csv_button.setEnabled(can_export)
        self.export_txt_button.setEnabled(can_export)

    def _set_status(self, message: str, color: str = COLOR_TEXT) -> None:
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color};")

    def _reset_results(self) -> None:
        self._open_ports.clear()
        self._services.clear()
        self._scanned = 0
        self.table.setRowCount(0)
        self._update_open_count()

    def _update_progress(self, scanned: int, total: int) -> None:
        self._scanned = scanned
        self.progress_bar.setRange(0, max(total, 1))
        self.progress_bar.setValue(scanned)
        percent = int(scanned * 100 / total) if total else 0
        self.scanned_label.setText(f"Scanned: {scanned} / {total}  ({percent}%)")
        self.summary_scanned.setText(str(scanned))

    def _update_open_count(self) -> None:
        count = len(self._open_ports)
        self.open_label.setText(f"Open: {count}")
        self.summary_open.setText(str(count))

    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(3000)
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setStyle("Fusion")
    app.setPalette(dark_palette())
    app.setStyleSheet(STYLESHEET)

    window = MainWindow()
    window.resize(860, 780)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
