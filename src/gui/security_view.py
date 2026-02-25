"""Security Operations Center view — IDS events, threat scores, anomaly alerts."""

from PySide6.QtCore import Qt, Slot
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


# Severity colors
_SEV_COLORS = {
    "critical": "#f38ba8",
    "high": "#fab387",
    "warning": "#f9e2af",
    "medium": "#f9e2af",
    "info": "#89b4fa",
    "low": "#a6e3a1",
}


class SecurityView(QWidget):
    """Security Operations Center — IDS events, threats, anomalies."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 8, 8, 8)

        # ── Row 1: Stat cards ──────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(6)
        self._card_threat_level = StatCard("Threat Level", "LOW")
        self._card_total_events = StatCard("Security Events", "0")
        self._card_critical = StatCard("Critical", "0")
        self._card_ids_rules = StatCard("IDS Rules Hit", "0")
        self._card_threats_scored = StatCard("Threats Scored", "0")
        self._card_anomalies = StatCard("Anomalies", "0")

        for card in (self._card_threat_level, self._card_total_events,
                     self._card_critical, self._card_ids_rules,
                     self._card_threats_scored, self._card_anomalies):
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # ── Row 2: Events chart + Top threat sources ───────────
        mid_row = QHBoxLayout()
        mid_row.setSpacing(6)

        self._events_chart = LiveChart(
            title="Security Events / min",
            y_label="Events",
            num_lines=3,
            line_labels=["IDS", "Threats", "Anomalies"],
            max_points=60,
        )
        mid_row.addWidget(self._events_chart, stretch=2)

        # Top threat sources table
        threat_panel = QVBoxLayout()
        threat_title = QLabel("Top Threat Sources")
        threat_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        threat_panel.addWidget(threat_title)

        self._threat_table = QTableWidget()
        self._threat_table.setColumnCount(3)
        self._threat_table.setHorizontalHeaderLabels(["IP Address", "Score", "Flags"])
        self._threat_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._threat_table.setMaximumHeight(200)
        self._apply_table_style(self._threat_table)
        threat_panel.addWidget(self._threat_table)
        mid_row.addLayout(threat_panel, stretch=1)

        layout.addLayout(mid_row)

        # ── Row 3: Events log table ───────────────────────────
        events_title = QLabel("Security Events Log")
        events_title.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 12px; padding: 2px;")
        layout.addWidget(events_title)

        self._events_table = QTableWidget()
        columns = ["Time", "Severity", "Rule/Category", "Title", "Source IP", "Dest IP", "Description"]
        self._events_table.setColumnCount(len(columns))
        self._events_table.setHorizontalHeaderLabels(columns)
        self._events_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._events_table.setAlternatingRowColors(True)
        self._events_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._apply_table_style(self._events_table)
        layout.addWidget(self._events_table, stretch=1)

        # Counters
        self._total_events = 0
        self._critical_count = 0
        self._ids_count = 0
        self._threat_count = 0
        self._anomaly_count = 0
        self._threat_scores: dict[str, int] = {}
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
        """Add a security event to the log."""
        self._total_events += 1
        severity = event.get("severity", "info").lower()
        rule_id = event.get("rule_id", event.get("category", ""))

        if severity == "critical":
            self._critical_count += 1

        # Classify source
        if rule_id.startswith("IDS_"):
            self._ids_count += 1
        elif rule_id.startswith("THREAT_") or "threat" in rule_id.lower():
            self._threat_count += 1
        elif rule_id.startswith("ANOMALY_") or "anomaly" in rule_id.lower():
            self._anomaly_count += 1

        # Update cards
        self._card_total_events.set_value(str(self._total_events))
        self._card_critical.set_value(str(self._critical_count))
        self._card_ids_rules.set_value(str(self._ids_count))
        self._card_threats_scored.set_value(str(self._threat_count))
        self._card_anomalies.set_value(str(self._anomaly_count))

        # Threat level
        if self._critical_count > 5:
            self._card_threat_level.set_value("CRITICAL")
        elif self._critical_count > 0 or self._total_events > 20:
            self._card_threat_level.set_value("HIGH")
        elif self._total_events > 5:
            self._card_threat_level.set_value("MEDIUM")
        else:
            self._card_threat_level.set_value("LOW")

        # Add to table
        row = self._events_table.rowCount()
        if row >= self._max_display:
            self._events_table.removeRow(0)
            row = self._events_table.rowCount()

        self._events_table.insertRow(row)

        time_str = event.get("timestamp", "")
        if "T" in time_str:
            time_str = time_str.split("T")[1][:8]

        items = [
            time_str,
            severity.upper(),
            rule_id,
            event.get("title", ""),
            event.get("src_ip", ""),
            event.get("dst_ip", ""),
            event.get("description", ""),
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            if col == 1:  # severity column
                color = _SEV_COLORS.get(severity, "#cdd6f4")
                item.setForeground(Qt.GlobalColor.white)
                item.setBackground(Qt.GlobalColor.transparent)
                from PySide6.QtGui import QColor
                item.setForeground(QColor(color))
            self._events_table.setItem(row, col, item)

        self._events_table.scrollToBottom()

    @Slot(str, int, dict)
    def update_threat_score(self, ip: str, score: int, details: dict):
        """Update threat scores display."""
        self._threat_scores[ip] = score
        sorted_threats = sorted(self._threat_scores.items(), key=lambda x: x[1], reverse=True)[:20]

        self._threat_table.setRowCount(len(sorted_threats))
        for row, (tip, tscore) in enumerate(sorted_threats):
            self._threat_table.setItem(row, 0, QTableWidgetItem(tip))
            score_item = QTableWidgetItem(str(tscore))
            if tscore > 80:
                from PySide6.QtGui import QColor
                score_item.setForeground(QColor("#f38ba8"))
            elif tscore > 60:
                from PySide6.QtGui import QColor
                score_item.setForeground(QColor("#f9e2af"))
            self._threat_table.setItem(row, 1, score_item)
            flags = ", ".join(details.get("factors", {}).keys()) if details else ""
            self._threat_table.setItem(row, 2, QTableWidgetItem(flags))

    def update_events_chart(self, ids: int, threats: int, anomalies: int):
        """Update the events-per-minute chart."""
        self._events_chart.add_data_point([ids, threats, anomalies])
