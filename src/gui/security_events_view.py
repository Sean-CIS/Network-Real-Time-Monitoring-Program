from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.stat_card import StatCard

_SEVERITY_COLORS = {
    "critical": QColor("#f38ba8"),
    "warning": QColor("#f9e2af"),
    "info": QColor("#94e2d5"),
}


class SecurityEventsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Controls row
        controls = QHBoxLayout()
        self._clear_btn = QPushButton("Clear All")
        self._clear_btn.setStyleSheet(
            "QPushButton { background-color: #f38ba8; color: #1e1e2e; "
            "padding: 8px 16px; border-radius: 4px; font-weight: bold; }"
        )
        controls.addWidget(self._clear_btn)

        self._severity_filter = QComboBox()
        self._severity_filter.addItems(["All", "Critical", "Warning", "Info"])
        self._severity_filter.currentTextChanged.connect(self._apply_filter)
        controls.addWidget(self._severity_filter)
        controls.addStretch()
        layout.addLayout(controls)

        # Stat cards
        cards = QHBoxLayout()
        self._card_total = StatCard("Total Events", "0")
        self._card_critical = StatCard("Critical", "0")
        self._card_warning = StatCard("Warning", "0")
        self._card_info = StatCard("Info", "0")
        cards.addWidget(self._card_total)
        cards.addWidget(self._card_critical)
        cards.addWidget(self._card_warning)
        cards.addWidget(self._card_info)
        cards.addStretch()
        layout.addLayout(cards)

        # Events table
        self._table = QTableWidget()
        columns = ["Time", "Severity", "Type", "Source IP", "Dest IP", "Description"]
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

        self._all_events: list[dict] = []

    @property
    def clear_button(self) -> QPushButton:
        return self._clear_btn

    def update_events(self, events: list[dict]):
        """Replace all events from DB query."""
        self._all_events = list(events)
        self._apply_filter(self._severity_filter.currentText())

    def add_event(self, event: dict):
        """Add a single new event (real-time)."""
        self._all_events.insert(0, event)
        self._apply_filter(self._severity_filter.currentText())

    def clear_events(self):
        self._table.setRowCount(0)
        self._all_events.clear()
        self._card_total.set_value("0")
        self._card_critical.set_value("0")
        self._card_warning.set_value("0")
        self._card_info.set_value("0")

    def _apply_filter(self, severity_text: str):
        filt = severity_text.lower()
        if filt == "all":
            filtered = self._all_events
        else:
            filtered = [e for e in self._all_events if e.get("severity") == filt]

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(filtered))
        counts = {"critical": 0, "warning": 0, "info": 0}

        for row, evt in enumerate(filtered):
            sev = evt.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
            color = _SEVERITY_COLORS.get(sev)

            ts = evt.get("timestamp", "")
            if "T" in ts:
                ts = ts.split("T")[1][:8]

            items = [
                ts,
                sev.upper(),
                evt.get("event_type", ""),
                evt.get("source_ip", ""),
                evt.get("dest_ip", ""),
                evt.get("description", ""),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                if color:
                    item.setForeground(color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

        # Update cards with totals from all events (not filtered)
        all_counts = {"critical": 0, "warning": 0, "info": 0}
        for e in self._all_events:
            s = e.get("severity", "info")
            all_counts[s] = all_counts.get(s, 0) + 1

        total = sum(all_counts.values())
        self._card_total.set_value(str(total))
        self._card_critical.set_value(str(all_counts["critical"]))
        self._card_warning.set_value(str(all_counts["warning"]))
        self._card_info.set_value(str(all_counts["info"]))
