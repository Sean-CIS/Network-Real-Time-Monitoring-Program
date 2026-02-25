from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
)

from src.gui.widgets.table_helpers import configure_table, set_item_with_tooltip


class DeviceTable(QTableWidget):
    """A sortable table for displaying discovered network devices."""

    device_selected = Signal(str)  # emits IP address

    COLUMNS = ["IP Address", "MAC Address", "Hostname", "OS", "Vendor", "Status", "Last Seen"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.setStyleSheet(
            """
            QTableWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                gridline-color: #45475a;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #45475a;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #cdd6f4;
                padding: 6px;
                border: 1px solid #45475a;
                font-weight: bold;
            }
            QTableWidget::item:alternate {
                background-color: #181825;
            }
            """
        )
        configure_table(self)
        self.cellClicked.connect(self._on_cell_clicked)

    def _on_cell_clicked(self, row: int, _col: int):
        ip_item = self.item(row, 0)
        if ip_item:
            self.device_selected.emit(ip_item.text())

    def update_devices(self, devices: list[dict]):
        self.setSortingEnabled(False)
        self.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            set_item_with_tooltip(self, row, 0, QTableWidgetItem(dev.get("ip", "")))
            set_item_with_tooltip(self, row, 1, QTableWidgetItem(dev.get("mac", "")))
            set_item_with_tooltip(self, row, 2, QTableWidgetItem(dev.get("hostname", "")))
            set_item_with_tooltip(self, row, 3, QTableWidgetItem(dev.get("os_info", "")))
            set_item_with_tooltip(self, row, 4, QTableWidgetItem(dev.get("vendor", "")))

            status = "Online" if dev.get("is_online") else "Offline"
            status_item = QTableWidgetItem(status)
            if dev.get("is_online"):
                status_item.setForeground(Qt.green)
            else:
                status_item.setForeground(Qt.red)
            set_item_with_tooltip(self, row, 5, status_item)

            set_item_with_tooltip(self, row, 6, QTableWidgetItem(dev.get("last_seen", "")))
        self.setSortingEnabled(True)
