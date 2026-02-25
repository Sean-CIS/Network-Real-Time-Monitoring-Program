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

from src.gui import theme
from src.gui.widgets.device_table import DeviceTable
from src.gui.widgets.ring_chart import RingChart
from src.gui.widgets.stat_card import StatCard


class DevicesView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # Header
        header = QHBoxLayout()
        title = QLabel("[ NETWORK DEVICES ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        header.addWidget(title)

        self._scan_btn = QPushButton("Scan Now")
        self._scan_btn.setStyleSheet(theme.BUTTON_PRIMARY)
        header.addWidget(self._scan_btn)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"color: {theme.GREEN_MUTED}; padding: 0 8px;")
        header.addWidget(self._status_label)
        header.addStretch()
        layout.addLayout(header)

        # Stat cards + device status ring chart
        cards_row = QHBoxLayout()
        self._card_total = StatCard("Total Devices", "0")
        self._card_online = StatCard("Online", "0")
        self._card_offline = StatCard("Offline", "0")
        self._card_rogue = StatCard("New/Unverified", "0")
        cards_row.addWidget(self._card_total)
        cards_row.addWidget(self._card_online)
        cards_row.addWidget(self._card_offline)
        cards_row.addWidget(self._card_rogue)

        self._status_ring = RingChart(title="Device Status")
        self._status_ring.setMaximumHeight(120)
        self._status_ring.setMaximumWidth(200)
        cards_row.addWidget(self._status_ring)
        cards_row.addStretch()
        layout.addLayout(cards_row)

        # Device table
        self._table = DeviceTable()
        layout.addWidget(self._table, stretch=1)

        # ARP Cache collapsible
        self._arp_header = QPushButton("\u25b6 ARP Cache")
        self._arp_header.setStyleSheet(theme.COLLAPSIBLE_HEADER)
        self._arp_header.clicked.connect(self._toggle_arp)
        layout.addWidget(self._arp_header)

        self._arp_table = QTableWidget()
        arp_cols = ["IP", "MAC", "Last Change"]
        self._arp_table.setColumnCount(len(arp_cols))
        self._arp_table.setHorizontalHeaderLabels(arp_cols)
        self._arp_table.setMaximumHeight(200)
        self._arp_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._arp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._arp_table.setStyleSheet(theme.TABLE_STYLE)
        self._arp_table.setVisible(False)
        layout.addWidget(self._arp_table)

        self._arp_changes: dict[str, str] = {}

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
        offline = total - online
        rogue = 0
        if trusted_macs is not None:
            rogue = sum(
                1 for d in devices
                if d.get("mac") and d["mac"] not in trusted_macs
            )
        self._card_total.set_value(str(total))
        self._card_online.set_value(str(online))
        self._card_offline.set_value(str(offline))
        self._card_rogue.set_value(str(rogue))

        # Color-code online/offline/rogue cards
        for child in self._card_online.findChildren(QLabel):
            if child.text() == str(online):
                child.setStyleSheet(
                    f"color: {theme.GREEN}; font-size: 20px; font-weight: bold;"
                )
        for child in self._card_offline.findChildren(QLabel):
            if child.text() == str(offline) and offline > 0:
                child.setStyleSheet(
                    f"color: {theme.RED}; font-size: 20px; font-weight: bold;"
                )
        for child in self._card_rogue.findChildren(QLabel):
            if child.text() == str(rogue) and rogue > 0:
                child.setStyleSheet(
                    f"color: {theme.AMBER}; font-size: 20px; font-weight: bold;"
                )

        # Status ring chart
        status_data = {}
        if online > 0:
            status_data["Online"] = online
        if offline > 0:
            status_data["Offline"] = offline
        if rogue > 0:
            status_data["Unverified"] = rogue
        self._status_ring.set_data(status_data)

    def update_arp_table(self, entries: list[dict]):
        self._arp_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            ip = entry.get("ip", "")
            mac = entry.get("mac", "")
            last_change = self._arp_changes.get(ip, "")
            self._arp_table.setItem(row, 0, QTableWidgetItem(ip))
            self._arp_table.setItem(row, 1, QTableWidgetItem(mac))
            self._arp_table.setItem(row, 2, QTableWidgetItem(last_change))

    def on_arp_change(self, change: dict):
        ip = change.get("ip", "")
        self._arp_changes[ip] = change.get("timestamp", "")[:19]
