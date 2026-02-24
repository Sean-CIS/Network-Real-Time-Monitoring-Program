from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.utils.vuln_hints import PORT_HINTS

_HINT_COLORS = {
    "critical": QColor(theme.RED),
    "warning": QColor(theme.AMBER),
    "info": QColor(theme.CYAN),
}


class PortsView(QWidget):
    quick_scan_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Input row
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target IP:"))
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("e.g. 192.168.1.1")
        self._target_input.setMaximumWidth(200)
        input_layout.addWidget(self._target_input)

        input_layout.addWidget(QLabel("Ports:"))
        self._ports_input = QLineEdit()
        self._ports_input.setPlaceholderText("e.g. 1-1024 or 22,80,443")
        self._ports_input.setMaximumWidth(200)
        input_layout.addWidget(self._ports_input)

        self._scan_btn = QPushButton("Scan Ports")
        self._scan_btn.setStyleSheet(theme.BUTTON_PRIMARY)
        input_layout.addWidget(self._scan_btn)

        self._quick_scan_btn = QPushButton("Quick Security Scan")
        self._quick_scan_btn.setStyleSheet(theme.BUTTON_ACCENT)
        self._quick_scan_btn.clicked.connect(self.quick_scan_clicked.emit)
        input_layout.addWidget(self._quick_scan_btn)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"color: {theme.GREEN_MUTED};")
        input_layout.addWidget(self._status_label)
        input_layout.addStretch()
        layout.addLayout(input_layout)

        # Results table with Security column
        self._table = QTableWidget()
        columns = ["Port", "Protocol", "State", "Service", "Version", "Security"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

    @property
    def scan_button(self) -> QPushButton:
        return self._scan_btn

    @property
    def quick_scan_button(self) -> QPushButton:
        return self._quick_scan_btn

    @property
    def target_ip(self) -> str:
        return self._target_input.text().strip()

    @property
    def port_range(self) -> str:
        return self._ports_input.text().strip()

    def set_target(self, ip: str):
        self._target_input.setText(ip)

    def set_status(self, status: str):
        self._status_label.setText(status)

    def update_results(self, ports: list[dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(ports))
        for row, p in enumerate(ports):
            port_num = p.get("port", 0)
            self._table.setItem(row, 0, QTableWidgetItem(str(port_num)))
            self._table.setItem(row, 1, QTableWidgetItem(p.get("protocol", "tcp")))
            state = p.get("state", "")
            self._table.setItem(row, 2, QTableWidgetItem(state))
            self._table.setItem(row, 3, QTableWidgetItem(p.get("service", "")))
            self._table.setItem(row, 4, QTableWidgetItem(p.get("version", "")))

            # Vulnerability hint
            hint_info = PORT_HINTS.get(port_num)
            if hint_info and state == "open":
                hint_item = QTableWidgetItem(hint_info["hint"])
                color = _HINT_COLORS.get(hint_info["severity"])
                if color:
                    hint_item.setForeground(color)
                self._table.setItem(row, 5, hint_item)
            else:
                self._table.setItem(row, 5, QTableWidgetItem(""))

        self._table.setSortingEnabled(True)
