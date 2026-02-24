from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
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

    @property
    def scan_button(self) -> QPushButton:
        return self._scan_btn

    @property
    def device_table(self) -> DeviceTable:
        return self._table

    def set_scan_status(self, status: str):
        self._status_label.setText(status)

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
