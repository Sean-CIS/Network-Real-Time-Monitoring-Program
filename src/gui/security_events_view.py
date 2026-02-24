"""Security Events view with active threat dashboard and firewall rule suggestions."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.gui.widgets.stat_card import StatCard

_SEVERITY_COLORS = {
    "critical": QColor(theme.RED),
    "warning": QColor(theme.AMBER),
    "info": QColor(theme.CYAN),
}

_THREAT_LEVELS = {
    "safe": (theme.GREEN, "SAFE"),
    "elevated": (theme.AMBER, "ELEVATED"),
    "critical": (theme.RED, "CRITICAL"),
}


class ThreatDashboard(QWidget):
    """Compact threat level dashboard panel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        # Threat level badge
        self._level_label = QLabel("[ SAFE ]")
        self._level_label.setStyleSheet(
            f"color: {theme.GREEN}; font-size: 16px; font-weight: bold; padding: 4px 12px;"
        )
        layout.addWidget(self._level_label)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color: {theme.BORDER};")
        layout.addWidget(sep)

        # Stats
        self._external_ips = QLabel("External IPs: 0")
        self._external_ips.setStyleSheet(f"color: {theme.GREEN_MUTED}; padding: 0 8px;")
        layout.addWidget(self._external_ips)

        self._unresolved = QLabel("Unresolved: 0")
        self._unresolved.setStyleSheet(f"color: {theme.GREEN_MUTED}; padding: 0 8px;")
        layout.addWidget(self._unresolved)

        self._events_24h = QLabel("24h Events: 0")
        self._events_24h.setStyleSheet(f"color: {theme.GREEN_MUTED}; padding: 0 8px;")
        layout.addWidget(self._events_24h)

        layout.addStretch()

        self.setStyleSheet(
            f"ThreatDashboard {{ background-color: {theme.BG_SURFACE}; "
            f"border: 1px solid {theme.BORDER}; border-radius: 2px; }}"
        )

    def update_threat_level(self, level: str):
        """Set threat level: 'safe', 'elevated', or 'critical'."""
        color, text = _THREAT_LEVELS.get(level, _THREAT_LEVELS["safe"])
        self._level_label.setText(f"[ {text} ]")
        self._level_label.setStyleSheet(
            f"color: {color}; font-size: 16px; font-weight: bold; padding: 4px 12px;"
        )

    def update_stats(self, external_ips: int = 0, unresolved: int = 0,
                     events_24h: int = 0):
        self._external_ips.setText(f"External IPs: {external_ips}")
        self._unresolved.setText(f"Unresolved: {unresolved}")
        self._events_24h.setText(f"24h Events: {events_24h}")


class FirewallRuleDialog(QDialog):
    """Dialog showing generated firewall rules with copy buttons."""

    def __init__(self, rules: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("[ FIREWALL RULE ]")
        self.setMinimumWidth(600)
        self.setStyleSheet(
            f"QDialog {{ background-color: {theme.BG_PRIMARY}; color: {theme.GREEN}; }}"
            f"QLabel {{ color: {theme.GREEN}; }}"
            f"QTextEdit {{ background-color: {theme.BG_SURFACE}; color: {theme.GREEN}; "
            f"border: 1px solid {theme.BORDER}; border-radius: 2px; "
            f'font-family: "Courier New", "Consolas", monospace; }}'
        )

        layout = QVBoxLayout(self)

        desc = QLabel(rules.get("desc", ""))
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size: 13px; padding: 4px;")
        layout.addWidget(desc)

        # Linux rule
        layout.addWidget(QLabel("Linux (iptables):"))
        linux_text = QTextEdit()
        linux_text.setPlainText(rules.get("linux", ""))
        linux_text.setReadOnly(True)
        linux_text.setMaximumHeight(60)
        layout.addWidget(linux_text)

        linux_copy = QPushButton("Copy Linux Command")
        linux_copy.setStyleSheet(theme.BUTTON_PRIMARY)
        linux_copy.clicked.connect(
            lambda: QApplication.clipboard().setText(rules.get("linux", ""))
        )
        layout.addWidget(linux_copy)

        # Windows rule
        layout.addWidget(QLabel("Windows (netsh):"))
        win_text = QTextEdit()
        win_text.setPlainText(rules.get("windows", ""))
        win_text.setReadOnly(True)
        win_text.setMaximumHeight(60)
        layout.addWidget(win_text)

        win_copy = QPushButton("Copy Windows Command")
        win_copy.setStyleSheet(theme.BUTTON_PRIMARY)
        win_copy.clicked.connect(
            lambda: QApplication.clipboard().setText(rules.get("windows", ""))
        )
        layout.addWidget(win_copy)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(theme.BUTTON_SECONDARY)
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)


class SecurityEventsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Active Threat Dashboard
        self._threat_dashboard = ThreatDashboard()
        layout.addWidget(self._threat_dashboard)

        # Controls row
        controls = QHBoxLayout()
        self._clear_btn = QPushButton("Clear All")
        self._clear_btn.setStyleSheet(theme.BUTTON_DANGER)
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

        # Events table with context menu
        self._table = QTableWidget()
        columns = ["Time", "Severity", "Type", "Source IP", "Dest IP", "Description"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

        self._all_events: list[dict] = []

    @property
    def clear_button(self) -> QPushButton:
        return self._clear_btn

    @property
    def threat_dashboard(self) -> ThreatDashboard:
        return self._threat_dashboard

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

    def _show_context_menu(self, pos):
        """Show context menu with firewall rule generation option."""
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._all_events):
            return

        menu = QMenu(self)
        menu.setStyleSheet(theme.CONTEXT_MENU)

        fw_action = QAction("Generate Firewall Rule", self)
        fw_action.triggered.connect(lambda: self._generate_firewall_rule(row))
        menu.addAction(fw_action)
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _generate_firewall_rule(self, row: int):
        """Generate and display a firewall rule for the selected event."""
        if row >= len(self._all_events):
            return

        # Get the currently displayed (filtered) event
        filt = self._severity_filter.currentText().lower()
        if filt == "all":
            filtered = self._all_events
        else:
            filtered = [e for e in self._all_events if e.get("severity") == filt]

        if row >= len(filtered):
            return

        event = filtered[row]

        from src.core.firewall_rules import generate_rule
        rules = generate_rule(event)
        dialog = FirewallRuleDialog(rules, self)
        dialog.exec()

    def _apply_filter(self, severity_text: str = "All"):
        filt = severity_text.lower()
        if filt == "all":
            filtered = self._all_events
        else:
            filtered = [e for e in self._all_events if e.get("severity") == filt]

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(filtered))

        for row, evt in enumerate(filtered):
            sev = evt.get("severity", "info")
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
