"""SET Defense Toolkit view — anti-phishing, credential leak, payload, DNS poisoning, C2 detection."""

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


_CATEGORY_COLORS = {
    "phishing": "#f38ba8",
    "credential_leak": "#fab387",
    "malware_payload": "#f9e2af",
    "dns_poisoning": "#cba6f7",
    "rogue_dhcp": "#94e2d5",
    "c2_beaconing": "#f38ba8",
}

_CATEGORY_LABELS = {
    "phishing": "Anti-Phishing",
    "credential_leak": "Credential Leak",
    "malware_payload": "Malware/Payload",
    "dns_poisoning": "DNS Poisoning",
    "rogue_dhcp": "Rogue DHCP",
    "c2_beaconing": "C2 Beaconing",
}


class SETDefenseView(QWidget):
    """SET Defense Toolkit — monitors for social engineering attacks."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 8, 8, 8)

        # ── Row 1: Stat cards ──────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(6)
        self._card_total = StatCard("SET Alerts", "0")
        self._card_phishing = StatCard("Phishing", "0")
        self._card_cred_leak = StatCard("Cred Leaks", "0")
        self._card_malware = StatCard("Malware", "0")
        self._card_dns_poison = StatCard("DNS Poison", "0")
        self._card_c2 = StatCard("C2 Beaconing", "0")

        for card in (self._card_total, self._card_phishing, self._card_cred_leak,
                     self._card_malware, self._card_dns_poison, self._card_c2):
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # ── Row 2: Chart + Protected Domains ───────────────────
        mid_row = QHBoxLayout()
        mid_row.setSpacing(6)

        self._defense_chart = LiveChart(
            title="SET Defense Events / min",
            y_label="Events",
            num_lines=4,
            line_labels=["Phishing", "Cred Leak", "Malware", "C2"],
            max_points=60,
        )
        mid_row.addWidget(self._defense_chart, stretch=2)

        # Category breakdown panel
        cat_panel = QVBoxLayout()
        cat_title = QLabel("Defense Categories")
        cat_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        cat_panel.addWidget(cat_title)

        self._category_table = QTableWidget()
        self._category_table.setColumnCount(3)
        self._category_table.setHorizontalHeaderLabels(["Category", "Events", "Severity"])
        self._category_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._category_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._category_table.setMaximumHeight(200)
        self._apply_table_style(self._category_table)

        # Pre-populate categories
        categories = ["phishing", "credential_leak", "malware_payload",
                       "dns_poisoning", "rogue_dhcp", "c2_beaconing"]
        self._category_table.setRowCount(len(categories))
        self._category_counts = {}
        for row, cat in enumerate(categories):
            label = _CATEGORY_LABELS.get(cat, cat)
            self._category_table.setItem(row, 0, QTableWidgetItem(label))
            self._category_table.setItem(row, 1, QTableWidgetItem("0"))
            self._category_table.setItem(row, 2, QTableWidgetItem("---"))
            self._category_counts[cat] = 0
        cat_panel.addWidget(self._category_table)

        mid_row.addLayout(cat_panel, stretch=1)
        layout.addLayout(mid_row)

        # ── Row 3: Events log table ───────────────────────────
        log_title = QLabel("SET Defense Events Log")
        log_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        layout.addWidget(log_title)

        self._events_table = QTableWidget()
        columns = ["Time", "Category", "Severity", "Title", "Source IP", "Description", "Action"]
        self._events_table.setColumnCount(len(columns))
        self._events_table.setHorizontalHeaderLabels(columns)
        self._events_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._events_table.setAlternatingRowColors(True)
        self._events_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._apply_table_style(self._events_table)
        layout.addWidget(self._events_table, stretch=1)

        self._total_events = 0
        self._max_display = 500

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
    def add_event(self, event: dict):
        """Add a SET defense event to the log."""
        self._total_events += 1
        category = event.get("category", "unknown")
        severity = event.get("severity", "warning")

        # Update counters
        if category in self._category_counts:
            self._category_counts[category] += 1

        self._card_total.set_value(str(self._total_events))
        self._card_phishing.set_value(str(self._category_counts.get("phishing", 0)))
        self._card_cred_leak.set_value(str(self._category_counts.get("credential_leak", 0)))
        self._card_malware.set_value(str(self._category_counts.get("malware_payload", 0)))
        self._card_dns_poison.set_value(str(self._category_counts.get("dns_poisoning", 0)))
        self._card_c2.set_value(str(self._category_counts.get("c2_beaconing", 0)))

        # Update category table
        categories = ["phishing", "credential_leak", "malware_payload",
                       "dns_poisoning", "rogue_dhcp", "c2_beaconing"]
        for row, cat in enumerate(categories):
            self._category_table.setItem(row, 1, QTableWidgetItem(
                str(self._category_counts.get(cat, 0))))
            if cat == category:
                sev_item = QTableWidgetItem(severity.upper())
                color = _CATEGORY_COLORS.get(cat, "#cdd6f4")
                sev_item.setForeground(QColor(color))
                self._category_table.setItem(row, 2, sev_item)

        # Add to events log
        row = self._events_table.rowCount()
        if row >= self._max_display:
            self._events_table.removeRow(0)
            row = self._events_table.rowCount()

        self._events_table.insertRow(row)

        time_str = event.get("timestamp", "")
        if "T" in time_str:
            time_str = time_str.split("T")[1][:8]

        cat_label = _CATEGORY_LABELS.get(category, category)
        items = [
            time_str,
            cat_label,
            severity.upper(),
            event.get("title", ""),
            event.get("src_ip", ""),
            event.get("description", ""),
            event.get("recommended_action", ""),
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            if col == 1:  # category
                color = _CATEGORY_COLORS.get(category, "#cdd6f4")
                item.setForeground(QColor(color))
            elif col == 2:  # severity
                sev_colors = {
                    "CRITICAL": "#f38ba8", "HIGH": "#fab387",
                    "WARNING": "#f9e2af", "MEDIUM": "#f9e2af",
                    "INFO": "#89b4fa", "LOW": "#a6e3a1",
                }
                item.setForeground(QColor(sev_colors.get(text, "#cdd6f4")))
            self._events_table.setItem(row, col, item)

        self._events_table.scrollToBottom()
