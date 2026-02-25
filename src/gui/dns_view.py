"""DNS Intelligence view — query log, top domains, stats, anomaly detection."""

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


class DNSView(QWidget):
    """DNS Intelligence tab — query log, top domains, stats."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 8, 8, 8)

        # ── Row 1: Stat cards ──────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(6)
        self._card_total = StatCard("Total Queries", "0")
        self._card_unique = StatCard("Unique Domains", "0")
        self._card_suspicious = StatCard("Suspicious", "0")
        self._card_nx = StatCard("NX Domains", "0")
        self._card_rate = StatCard("Queries/min", "0")
        self._card_top_type = StatCard("Top Query Type", "---")

        for card in (self._card_total, self._card_unique, self._card_suspicious,
                     self._card_nx, self._card_rate, self._card_top_type):
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # ── Row 2: Chart + Top Domains ─────────────────────────
        mid_row = QHBoxLayout()
        mid_row.setSpacing(6)

        self._dns_chart = LiveChart(
            title="DNS Queries / sec",
            y_label="Queries",
            num_lines=2,
            line_labels=["Total", "Suspicious"],
            max_points=120,
        )
        mid_row.addWidget(self._dns_chart, stretch=2)

        # Top domains panel
        top_panel = QVBoxLayout()
        top_title = QLabel("Top Queried Domains")
        top_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        top_panel.addWidget(top_title)

        self._top_domains_table = QTableWidget()
        self._top_domains_table.setColumnCount(3)
        self._top_domains_table.setHorizontalHeaderLabels(["Domain", "Count", "Status"])
        self._top_domains_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._top_domains_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._top_domains_table.setMaximumHeight(200)
        self._apply_table_style(self._top_domains_table)
        top_panel.addWidget(self._top_domains_table)
        mid_row.addLayout(top_panel, stretch=1)

        layout.addLayout(mid_row)

        # ── Row 3: Query log table ─────────────────────────────
        log_title = QLabel("DNS Query Log")
        log_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        layout.addWidget(log_title)

        self._query_table = QTableWidget()
        columns = ["Time", "Source IP", "Domain", "Type", "Response", "Status"]
        self._query_table.setColumnCount(len(columns))
        self._query_table.setHorizontalHeaderLabels(columns)
        self._query_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._query_table.setAlternatingRowColors(True)
        self._query_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._apply_table_style(self._query_table)
        layout.addWidget(self._query_table, stretch=1)

        self._max_display = 500
        self._query_count = 0

    def _apply_table_style(self, table: QTableWidget):
        table.setStyleSheet("""
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
        """)

    @Slot(dict)
    def add_query(self, query: dict):
        """Add a DNS query to the log."""
        self._query_count += 1

        row = self._query_table.rowCount()
        if row >= self._max_display:
            self._query_table.removeRow(0)
            row = self._query_table.rowCount()

        self._query_table.insertRow(row)

        time_str = query.get("timestamp", "")
        if "T" in time_str:
            time_str = time_str.split("T")[1][:8]

        domain = query.get("query_name", query.get("dns_query", ""))
        suspicious = query.get("is_suspicious", False)
        rcode = query.get("response_code", query.get("dns_rcode", ""))

        items = [
            time_str,
            query.get("src_ip", query.get("src", "")),
            domain,
            query.get("query_type", query.get("dns_qtype", "")),
            query.get("response_ips", query.get("dns_response", "")),
            "SUSPICIOUS" if suspicious else rcode or "OK",
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            if col == 5 and suspicious:
                item.setForeground(QColor("#f38ba8"))
            elif col == 5 and rcode == "NXDOMAIN":
                item.setForeground(QColor("#f9e2af"))
            self._query_table.setItem(row, col, item)

        self._query_table.scrollToBottom()

    @Slot(dict)
    def update_stats(self, stats: dict):
        """Update DNS statistics cards."""
        self._card_total.set_value(str(stats.get("total_queries", 0)))
        self._card_unique.set_value(str(stats.get("unique_domains", 0)))
        self._card_suspicious.set_value(str(stats.get("suspicious_count", 0)))
        self._card_nx.set_value(str(stats.get("nx_count", 0)))
        self._card_rate.set_value(f"{stats.get('queries_per_min', 0):.0f}")

        # Top query type
        qtypes = stats.get("query_types", {})
        if qtypes:
            top = max(qtypes, key=qtypes.get)
            self._card_top_type.set_value(top)

        # Top domains
        top_domains = stats.get("top_domains", {})
        if top_domains:
            sorted_domains = sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:20]
            self._top_domains_table.setRowCount(len(sorted_domains))
            suspicious_domains = stats.get("suspicious_domains", set())
            for row, (domain, count) in enumerate(sorted_domains):
                self._top_domains_table.setItem(row, 0, QTableWidgetItem(domain))
                self._top_domains_table.setItem(row, 1, QTableWidgetItem(str(count)))
                status = "SUSPICIOUS" if domain in suspicious_domains else "Normal"
                status_item = QTableWidgetItem(status)
                if status == "SUSPICIOUS":
                    status_item.setForeground(QColor("#f38ba8"))
                self._top_domains_table.setItem(row, 2, status_item)

        # Chart data
        total_rate = stats.get("queries_per_min", 0) / 60.0  # per sec
        suspicious_rate = stats.get("suspicious_count", 0)
        self._dns_chart.add_data_point([total_rate, suspicious_rate * 0.01])
