"""DNS Cache/History Viewer tab."""

from PySide6.QtCore import Slot
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
from src.gui.widgets.stat_card import StatCard
from src.utils import db


class DNSView(QWidget):
    """DNS history viewer with search and statistics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        title = QLabel("[ DNS HISTORY ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        layout.addWidget(title)

        # Search row
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search DNS queries (e.g. google.com)...")
        self._search_input.setStyleSheet(theme.INPUT_STYLE)
        self._search_input.returnPressed.connect(self._do_search)
        search_row.addWidget(self._search_input)

        self._search_btn = QPushButton("Search")
        self._search_btn.setStyleSheet(theme.BUTTON_PRIMARY)
        self._search_btn.clicked.connect(self._do_search)
        search_row.addWidget(self._search_btn)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setStyleSheet(theme.BUTTON_CYAN)
        self._refresh_btn.clicked.connect(self.refresh)
        search_row.addWidget(self._refresh_btn)
        search_row.addStretch()
        layout.addLayout(search_row)

        # Stat cards
        cards = QHBoxLayout()
        self._card_total = StatCard("Total Queries", "0")
        self._card_unique = StatCard("Unique Domains", "0")
        self._card_nxdomain = StatCard("No Response", "0")
        cards.addWidget(self._card_total)
        cards.addWidget(self._card_unique)
        cards.addWidget(self._card_nxdomain)
        cards.addStretch()
        layout.addLayout(cards)

        # DNS history table
        self._table = QTableWidget()
        columns = ["Time", "Query", "Type", "Response", "Source IP"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

    def refresh(self):
        """Load latest DNS records from database."""
        records = db.get_recent_dns(500)
        self._populate_table(records)
        self._update_stats()

    def _do_search(self):
        query = self._search_input.text().strip()
        if query:
            records = db.search_dns(query, 500)
        else:
            records = db.get_recent_dns(500)
        self._populate_table(records)
        self._update_stats()

    def _populate_table(self, records: list[dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(records))
        for row, rec in enumerate(records):
            ts = rec.get("timestamp", "")
            if "T" in ts:
                ts = ts.split("T")[1][:8]
            items = [
                ts,
                rec.get("query", ""),
                rec.get("query_type", ""),
                rec.get("response", ""),
                rec.get("source_ip", ""),
            ]
            for col, text in enumerate(items):
                self._table.setItem(row, col, QTableWidgetItem(str(text or "")))
        self._table.setSortingEnabled(True)

    def _update_stats(self):
        stats = db.get_dns_stats()
        self._card_total.set_value(str(stats.get("total", 0)))
        self._card_unique.set_value(str(stats.get("unique_domains", 0)))
        self._card_nxdomain.set_value(str(stats.get("nxdomain", 0)))
