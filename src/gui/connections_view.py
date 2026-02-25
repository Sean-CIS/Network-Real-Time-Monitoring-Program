from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt

from src.gui import theme
from src.gui.widgets.ring_chart import RingChart
from src.gui.widgets.stat_card import StatCard

# State-based text colors — CRT palette
_STATE_COLORS = {
    "ESTABLISHED": QColor(theme.GREEN),
    "CLOSE_WAIT": QColor(theme.AMBER),
    "TIME_WAIT": QColor(theme.AMBER),
    "FIN_WAIT1": QColor(theme.AMBER),
    "FIN_WAIT2": QColor(theme.AMBER),
    "LAST_ACK": QColor(theme.RED),
    "LISTEN": QColor(theme.CYAN),
    "SYN_SENT": QColor(theme.AMBER),
    "SYN_RECV": QColor(theme.AMBER),
    "NONE": QColor(theme.GREEN_MUTED),
}
_SUSPICIOUS_BG = QColor(255, 51, 51, 30)
_NEW_DEST_BG = QColor(0, 255, 65, 20)

# State badge labels
_STATE_BADGES = {
    "ESTABLISHED": "\u25cf ESTABLISHED",
    "LISTEN": "\u25cb LISTEN",
    "CLOSE_WAIT": "\u25b2 CLOSE_WAIT",
    "TIME_WAIT": "\u25b2 TIME_WAIT",
    "FIN_WAIT1": "\u25b2 FIN_WAIT1",
    "FIN_WAIT2": "\u25b2 FIN_WAIT2",
    "LAST_ACK": "\u25b2 LAST_ACK",
    "SYN_SENT": "\u25b7 SYN_SENT",
    "SYN_RECV": "\u25b7 SYN_RECV",
}


def _format_bytes(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    elif b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    elif b > 0:
        return f"{b} B"
    return "\u2014"


class ConnectionsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # ── Header ──────────────────────────────────────────────
        header = QHBoxLayout()
        title = QLabel("[ ACTIVE CONNECTIONS ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        header.addWidget(title)

        self._conn_count_badge = QLabel("0")
        self._conn_count_badge.setStyleSheet(
            f"color: {theme.BG_DARKEST}; background-color: {theme.GREEN}; "
            f"font-size: 11px; font-weight: bold; padding: 2px 8px; "
            f"border-radius: 2px;"
        )
        header.addWidget(self._conn_count_badge)
        header.addStretch()

        # Filter
        header.addWidget(QLabel("Filter:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("process, IP, port...")
        self._filter_input.setStyleSheet(theme.INPUT_STYLE)
        self._filter_input.setMaximumWidth(250)
        self._filter_input.textChanged.connect(self._apply_filter)
        header.addWidget(self._filter_input)
        layout.addLayout(header)

        # ── Stats row: cards + state ring chart ──────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(6)

        self._card_total = StatCard("Total", "0", sparkline=True)
        self._card_established = StatCard("Established", "0")
        self._card_listening = StatCard("Listening", "0")
        self._card_suspicious = StatCard("Suspicious", "0")
        stats_row.addWidget(self._card_total)
        stats_row.addWidget(self._card_established)
        stats_row.addWidget(self._card_listening)
        stats_row.addWidget(self._card_suspicious)

        # State distribution ring chart
        self._state_ring = RingChart(title="State Distribution")
        self._state_ring.setMaximumHeight(120)
        self._state_ring.setMaximumWidth(220)
        stats_row.addWidget(self._state_ring)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # ── Connections table ────────────────────────────────────
        self._table = QTableWidget()
        columns = [
            "PID", "Process", "Local Address", "Remote Address",
            "State", "Bytes In", "Bytes Out",
        ]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

        self._all_connections: list[dict] = []

    def update_connections(self, conns: list[dict]):
        self._all_connections = conns
        self._apply_filter()

    def _apply_filter(self):
        filter_text = self._filter_input.text().strip().lower()
        conns = self._all_connections

        if filter_text:
            conns = [
                c for c in conns
                if (filter_text in str(c.get("pid", "")).lower()
                    or filter_text in c.get("process", "").lower()
                    or filter_text in c.get("local_addr", "").lower()
                    or filter_text in c.get("remote_addr", "").lower()
                    or filter_text in c.get("state", "").lower())
            ]

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(conns))

        established = 0
        listening = 0
        suspicious = 0
        state_counts: dict[str, int] = {}

        for row, c in enumerate(conns):
            state = c.get("state", "")
            state_counts[state] = state_counts.get(state, 0) + 1
            if state == "ESTABLISHED":
                established += 1
            elif state == "LISTEN":
                listening += 1
            is_suspicious = c.get("highlight", False)
            if is_suspicious:
                suspicious += 1
            is_new = c.get("is_new_dest", False)

            state_color = _STATE_COLORS.get(state)
            if is_suspicious:
                bg_color = _SUSPICIOUS_BG
            elif is_new:
                bg_color = _NEW_DEST_BG
            else:
                bg_color = None

            items_data = [
                c.get("pid", ""),
                c.get("process", ""),
                c.get("local_addr", ""),
                c.get("remote_addr", ""),
                _STATE_BADGES.get(state, state),
                _format_bytes(c.get("bytes_in", 0)),
                _format_bytes(c.get("bytes_out", 0)),
            ]
            for col, text in enumerate(items_data):
                item = QTableWidgetItem(str(text))
                if is_suspicious:
                    item.setForeground(QColor(theme.RED))
                elif is_new:
                    item.setForeground(QColor(theme.CYAN))
                elif col == 4 and state_color:
                    # State column gets state color
                    item.setForeground(state_color)
                elif state_color:
                    item.setForeground(state_color)
                if bg_color:
                    item.setBackground(bg_color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        self._table.sortByColumn(1, self._table.horizontalHeader().sortIndicatorOrder())

        total = len(self._all_connections)
        self._conn_count_badge.setText(str(total))
        self._card_total.set_value(str(total))
        self._card_total.add_spark_point(float(total))
        self._card_established.set_value(str(established))
        self._card_listening.set_value(str(listening))
        self._card_suspicious.set_value(str(suspicious))

        # Color-code suspicious card
        if suspicious > 0:
            for child in self._card_suspicious.findChildren(QLabel):
                if child.text() == str(suspicious):
                    child.setStyleSheet(
                        f"color: {theme.RED}; font-size: 20px; font-weight: bold;"
                    )
                    break

        # Update state distribution ring chart
        self._state_ring.set_data(state_counts)
