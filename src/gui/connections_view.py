"""Active network connections view with GeoIP enrichment."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.stat_card import StatCard
from src.gui.widgets.table_helpers import configure_table, set_item_with_tooltip


class ConnectionsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Header
        header = QHBoxLayout()
        title = QLabel("Active Network Connections")
        title.setStyleSheet("color: #cdd6f4; font-size: 16px; font-weight: bold; padding: 4px;")
        self._status_label = QLabel("Monitoring...")
        self._status_label.setStyleSheet("color: #a6adc8;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._status_label)
        layout.addLayout(header)

        # Stat cards
        cards = QHBoxLayout()
        self._card_total = StatCard("Total Connections", "0")
        self._card_established = StatCard("Established", "0")
        self._card_countries = StatCard("Countries", "0")
        self._card_processes = StatCard("Processes", "0")
        cards.addWidget(self._card_total)
        cards.addWidget(self._card_established)
        cards.addWidget(self._card_countries)
        cards.addWidget(self._card_processes)
        cards.addStretch()
        layout.addLayout(cards)

        # Connections table
        columns = [
            "Process", "Protocol", "Service", "Local Address", "Remote Address",
            "Status", "Country", "City",
        ]
        self._table = QTableWidget()
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
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
        configure_table(self._table)
        layout.addWidget(self._table, stretch=1)

        self._geoip_data: dict[str, dict] = {}

    def set_geoip_data(self, data: dict[str, dict]):
        self._geoip_data = data

    def update_connections(self, connections: list[dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(connections))

        countries = set()
        processes = set()
        established = 0

        for row, conn in enumerate(connections):
            process = conn.get("process", "")
            proto = conn.get("protocol", "")
            service = conn.get("service", "")
            local = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
            remote_ip = conn.get("remote_ip", "")
            remote = f"{remote_ip}:{conn.get('remote_port', '')}"
            status = conn.get("status", "")

            # GeoIP enrichment
            geo = self._geoip_data.get(remote_ip, {})
            country = geo.get("country", "")
            city = geo.get("city", "")

            if country:
                countries.add(country)
            if process:
                processes.add(process)
            if status == "ESTABLISHED":
                established += 1

            set_item_with_tooltip(self._table, row, 0, QTableWidgetItem(process))
            set_item_with_tooltip(self._table, row, 1, QTableWidgetItem(proto))
            set_item_with_tooltip(self._table, row, 2, QTableWidgetItem(service))
            set_item_with_tooltip(self._table, row, 3, QTableWidgetItem(local))
            set_item_with_tooltip(self._table, row, 4, QTableWidgetItem(remote))

            status_item = QTableWidgetItem(status)
            if status == "ESTABLISHED":
                status_item.setForeground(Qt.green)
            elif status in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"):
                status_item.setForeground(Qt.yellow)
            elif status == "LISTEN":
                status_item.setForeground(Qt.cyan)
            set_item_with_tooltip(self._table, row, 5, status_item)

            set_item_with_tooltip(self._table, row, 6, QTableWidgetItem(country))
            set_item_with_tooltip(self._table, row, 7, QTableWidgetItem(city))

        self._table.setSortingEnabled(True)

        self._card_total.set_value(str(len(connections)))
        self._card_established.set_value(str(established))
        self._card_countries.set_value(str(len(countries)))
        self._card_processes.set_value(str(len(processes)))
        self._status_label.setText(f"Live — {len(connections)} connections")
