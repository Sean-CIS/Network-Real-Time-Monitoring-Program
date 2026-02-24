from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.gui.widgets.stat_card import StatCard


class AlertsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        self._clear_btn = QPushButton("Clear All")
        self._clear_btn.setStyleSheet(theme.BUTTON_DANGER)
        controls.addWidget(self._clear_btn)
        controls.addStretch()
        layout.addLayout(controls)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_total = StatCard("Total Alerts", "0")
        self._card_critical = StatCard("Critical", "0")
        self._card_warning = StatCard("Warning", "0")
        self._card_info = StatCard("Info", "0")
        cards_layout.addWidget(self._card_total)
        cards_layout.addWidget(self._card_critical)
        cards_layout.addWidget(self._card_warning)
        cards_layout.addWidget(self._card_info)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Alert table
        self._table = QTableWidget()
        columns = ["Time", "Severity", "Type", "Message", "Source"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

    @property
    def clear_button(self) -> QPushButton:
        return self._clear_btn

    def update_alerts(self, alerts: list[dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(alerts))

        counts = {"critical": 0, "warning": 0, "info": 0}
        for row, a in enumerate(alerts):
            self._table.setItem(row, 0, QTableWidgetItem(a.get("timestamp", "")))

            severity = a.get("severity", "info")
            sev_item = QTableWidgetItem(severity.upper())
            if severity == "critical":
                sev_item.setForeground(QColor(theme.RED))
                counts["critical"] += 1
            elif severity == "warning":
                sev_item.setForeground(QColor(theme.AMBER))
                counts["warning"] += 1
            else:
                sev_item.setForeground(QColor(theme.CYAN))
                counts["info"] += 1
            self._table.setItem(row, 1, sev_item)

            self._table.setItem(row, 2, QTableWidgetItem(a.get("alert_type", "")))
            self._table.setItem(row, 3, QTableWidgetItem(a.get("message", "")))
            self._table.setItem(row, 4, QTableWidgetItem(a.get("source", "")))

        self._table.setSortingEnabled(True)
        self._card_total.set_value(str(len(alerts)))
        self._card_critical.set_value(str(counts["critical"]))
        self._card_warning.set_value(str(counts["warning"]))
        self._card_info.set_value(str(counts["info"]))

    def clear_alerts(self):
        self._table.setRowCount(0)
        self._card_total.set_value("0")
        self._card_critical.set_value("0")
        self._card_warning.set_value("0")
        self._card_info.set_value("0")
