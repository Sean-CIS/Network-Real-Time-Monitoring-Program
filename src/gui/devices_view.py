from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.device_table import DeviceTable
from src.gui.widgets.stat_card import StatCard


class DevicesView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Header row
        header = QHBoxLayout()
        self._scan_btn = QPushButton("Scan Now")
        self._scan_btn.setStyleSheet(
            "QPushButton { background-color: #89b4fa; color: #1e1e2e; "
            "padding: 8px 16px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #74c7ec; }"
        )
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #a6adc8;")
        header.addWidget(self._scan_btn)
        header.addWidget(self._status_label)
        header.addStretch()
        layout.addLayout(header)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_total = StatCard("Total Devices", "0")
        self._card_online = StatCard("Online", "0")
        self._card_offline = StatCard("Offline", "0")
        self._card_rogue = StatCard("New/Unverified", "0")
        cards_layout.addWidget(self._card_total)
        cards_layout.addWidget(self._card_online)
        cards_layout.addWidget(self._card_offline)
        cards_layout.addWidget(self._card_rogue)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Device table
        self._table = DeviceTable()
        layout.addWidget(self._table, stretch=1)

        # ARP Cache collapsible sub-panel
        self._arp_header = QPushButton("\u25b6 ARP Cache")
        self._arp_header.setStyleSheet(
            "QPushButton { color: #cdd6f4; font-size: 13px; font-weight: bold; "
            "background: transparent; border: none; text-align: left; padding: 4px; }"
            "QPushButton:hover { color: #89b4fa; }"
        )
        self._arp_header.clicked.connect(self._toggle_arp)
        layout.addWidget(self._arp_header)

        self._arp_table = QTableWidget()
        arp_cols = ["IP", "MAC", "Last Change"]
        self._arp_table.setColumnCount(len(arp_cols))
        self._arp_table.setHorizontalHeaderLabels(arp_cols)
        self._arp_table.setMaximumHeight(200)
        self._arp_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._arp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._arp_table.setStyleSheet(
            """
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4;
                gridline-color: #45475a; border: none;
            }
            QHeaderView::section {
                background-color: #313244; color: #cdd6f4;
                padding: 4px; border: 1px solid #45475a; font-weight: bold;
            }
            """
        )
        self._arp_table.setVisible(False)
        layout.addWidget(self._arp_table)

        self._arp_changes: dict[str, str] = {}  # ip -> timestamp of last change

    @property
    def scan_button(self) -> QPushButton:
        return self._scan_btn

    @property
    def device_table(self) -> DeviceTable:
        return self._table

    def set_scan_status(self, status: str):
        self._status_label.setText(status)

    def _toggle_arp(self):
        visible = not self._arp_table.isVisible()
        self._arp_table.setVisible(visible)
        self._arp_header.setText(
            "\u25bc ARP Cache" if visible else "\u25b6 ARP Cache"
        )

    def update_devices(self, devices: list[dict], trusted_macs: set[str] | None = None):
        self._table.update_devices(devices, trusted_macs)
        total = len(devices)
        online = sum(1 for d in devices if d.get("is_online"))
        rogue = 0
        if trusted_macs is not None:
            rogue = sum(
                1 for d in devices
                if d.get("mac") and d["mac"] not in trusted_macs
            )
        self._card_total.set_value(str(total))
        self._card_online.set_value(str(online))
        self._card_offline.set_value(str(total - online))
        self._card_rogue.set_value(str(rogue))

    def update_arp_table(self, entries: list[dict]):
        """Update the ARP cache sub-panel table."""
        self._arp_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            ip = entry.get("ip", "")
            mac = entry.get("mac", "")
            last_change = self._arp_changes.get(ip, "")
            self._arp_table.setItem(row, 0, QTableWidgetItem(ip))
            self._arp_table.setItem(row, 1, QTableWidgetItem(mac))
            self._arp_table.setItem(row, 2, QTableWidgetItem(last_change))

    def on_arp_change(self, change: dict):
        """Record an ARP MAC change timestamp for display."""
        ip = change.get("ip", "")
        self._arp_changes[ip] = change.get("timestamp", "")[:19]
