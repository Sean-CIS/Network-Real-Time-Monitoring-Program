from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHeaderView,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
)

from src.gui import theme

_ROGUE_BG = QColor(255, 176, 0, 30)  # amber tint for unverified devices


class DeviceTable(QTableWidget):
    """A sortable table for displaying discovered network devices."""

    device_selected = Signal(str)  # emits IP address
    trust_device = Signal(str)     # emits MAC address to mark as trusted

    COLUMNS = ["IP Address", "MAC Address", "Hostname", "OS", "Vendor", "Status", "Last Seen"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setStyleSheet(theme.TABLE_STYLE)
        self.cellClicked.connect(self._on_cell_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

    def _on_cell_clicked(self, row: int, _col: int):
        ip_item = self.item(row, 0)
        if ip_item:
            self.device_selected.emit(ip_item.text())

    def _context_menu(self, pos):
        row = self.rowAt(pos.y())
        if row < 0:
            return
        mac_item = self.item(row, 1)
        if not mac_item or not mac_item.text():
            return
        menu = QMenu(self)
        menu.setStyleSheet(theme.CONTEXT_MENU)
        trust_action = menu.addAction("Mark as Trusted")
        action = menu.exec(self.viewport().mapToGlobal(pos))
        if action == trust_action:
            self.trust_device.emit(mac_item.text())

    def update_devices(self, devices: list[dict], trusted_macs: set[str] | None = None):
        self.setSortingEnabled(False)
        self.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            mac = dev.get("mac", "")
            is_rogue = (
                trusted_macs is not None
                and mac
                and mac not in trusted_macs
            )

            items_data = [
                dev.get("ip", ""),
                mac,
                dev.get("hostname", ""),
                dev.get("os_info", ""),
                dev.get("vendor", ""),
            ]
            for col, text in enumerate(items_data):
                item = QTableWidgetItem(text)
                if is_rogue:
                    item.setBackground(_ROGUE_BG)
                    item.setForeground(QColor(theme.AMBER))
                self.setItem(row, col, item)

            status = "Online" if dev.get("is_online") else "Offline"
            status_item = QTableWidgetItem(status)
            if dev.get("is_online"):
                status_item.setForeground(QColor(theme.GREEN))
            else:
                status_item.setForeground(QColor(theme.RED))
            if is_rogue:
                status_item.setBackground(_ROGUE_BG)
            self.setItem(row, 5, status_item)

            last_seen_item = QTableWidgetItem(dev.get("last_seen", ""))
            if is_rogue:
                last_seen_item.setBackground(_ROGUE_BG)
                last_seen_item.setForeground(QColor(theme.AMBER))
            self.setItem(row, 6, last_seen_item)
        self.setSortingEnabled(True)
