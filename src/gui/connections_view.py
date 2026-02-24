from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.gui.widgets.stat_card import StatCard

# State-based text colors — CRT palette
_STATE_COLORS = {
    "ESTABLISHED": QColor(theme.GREEN),        # phosphor green
    "CLOSE_WAIT": QColor(theme.AMBER),         # amber
    "TIME_WAIT": QColor(theme.AMBER),
    "FIN_WAIT1": QColor(theme.AMBER),
    "FIN_WAIT2": QColor(theme.AMBER),
    "LAST_ACK": QColor(theme.AMBER),
    "LISTEN": QColor(theme.GREEN_MUTED),       # dim green
    "NONE": QColor(theme.GREEN_MUTED),
}
_SUSPICIOUS_BG = QColor(255, 51, 51, 30)       # red tint
_NEW_DEST_BG = QColor(0, 255, 65, 20)          # green tint


def _format_bytes(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    elif b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    elif b > 0:
        return f"{b} B"
    return ""


class ConnectionsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Filter row
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filter by process, IP, or port...")
        self._filter_input.setStyleSheet(theme.INPUT_STYLE)
        self._filter_input.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._filter_input)
        filter_row.addStretch()
        layout.addLayout(filter_row)

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

        # Connections table — with bandwidth columns
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

        for row, c in enumerate(conns):
            state = c.get("state", "")
            if state == "ESTABLISHED":
                established += 1
            elif state == "LISTEN":
                listening += 1
            is_suspicious = c.get("highlight", False)
            if is_suspicious:
                suspicious += 1
            is_new = c.get("is_new_dest", False)

            # Determine colors for this row
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
                state,
                _format_bytes(c.get("bytes_in", 0)),
                _format_bytes(c.get("bytes_out", 0)),
            ]
            for col, text in enumerate(items_data):
                item = QTableWidgetItem(str(text))
                if is_suspicious:
                    item.setForeground(QColor(theme.RED))
                elif is_new:
                    item.setForeground(QColor(theme.CYAN))
                elif state_color:
                    item.setForeground(state_color)
                if bg_color:
                    item.setBackground(bg_color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        # Sort by process name (column 1) ascending by default
        self._table.sortByColumn(1, self._table.horizontalHeader().sortIndicatorOrder())

        self._card_total.set_value(str(len(self._all_connections)))
        self._card_established.set_value(str(established))
        self._card_listening.set_value(str(listening))
        self._card_suspicious.set_value(str(suspicious))
