from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.stat_card import StatCard

_SUSPICIOUS_BG = QColor(249, 226, 175, 50)  # yellow tint


class ConnectionsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Stat cards
        cards = QHBoxLayout()
        self._card_total = StatCard("Active Connections", "0")
        self._card_established = StatCard("Established", "0")
        self._card_listening = StatCard("Listening", "0")
        self._card_suspicious = StatCard("Suspicious", "0")
        cards.addWidget(self._card_total)
        cards.addWidget(self._card_established)
        cards.addWidget(self._card_listening)
        cards.addWidget(self._card_suspicious)
        cards.addStretch()
        layout.addLayout(cards)

        # Connections table
        self._table = QTableWidget()
        columns = ["PID", "Process", "Local Address", "Remote Address", "State"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(
            """
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4;
                gridline-color: #45475a; border: none;
            }
            QTableWidget::item:selected { background-color: #45475a; }
            QHeaderView::section {
                background-color: #313244; color: #cdd6f4;
                padding: 6px; border: 1px solid #45475a; font-weight: bold;
            }
            QTableWidget::item:alternate { background-color: #181825; }
            """
        )
        layout.addWidget(self._table, stretch=1)

    def update_connections(self, conns: list[dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(conns))

        established = 0
        listening = 0
        suspicious = 0

        for row, c in enumerate(conns):
            state = c.get("state", "")
            if state == "ESTABLISHED":
                established += 1
            elif state == "LISTEN":
                listening += 1
            is_suspicious = c.get("highlight", False)
            if is_suspicious:
                suspicious += 1

            items_data = [
                c.get("pid", ""),
                c.get("process", ""),
                c.get("local_addr", ""),
                c.get("remote_addr", ""),
                state,
            ]
            for col, text in enumerate(items_data):
                item = QTableWidgetItem(str(text))
                if is_suspicious:
                    item.setForeground(QColor("#f9e2af"))
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

        self._card_total.set_value(str(len(conns)))
        self._card_established.set_value(str(established))
        self._card_listening.set_value(str(listening))
        self._card_suspicious.set_value(str(suspicious))
