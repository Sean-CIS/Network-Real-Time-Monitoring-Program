"""Shared table configuration for resizable, interactive columns with tooltips."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


# Column width defaults by content type keyword
_WIDTH_MAP = {
    "time": 180,
    "timestamp": 180,
    "ip": 140,
    "address": 140,
    "mac": 160,
    "severity": 100,
    "status": 100,
    "state": 100,
    "port": 80,
    "protocol": 100,
    "proto": 100,
    "type": 100,
    "category": 120,
    "count": 80,
    "score": 80,
    "country": 120,
    "city": 120,
    "process": 140,
    "service": 120,
    "vendor": 140,
    "hostname": 160,
    "os": 120,
    "version": 120,
    "flags": 140,
    "rule": 140,
}

# Keywords indicating stretch columns
_STRETCH_KEYWORDS = {"message", "description", "info", "action", "domain", "title", "response"}


def configure_table(table: QTableWidget):
    """Apply interactive resizable columns, sensible widths, tooltips, and scrollbar."""
    header = table.horizontalHeader()
    col_count = table.columnCount()

    # Make all columns interactive (draggable)
    header.setSectionResizeMode(QHeaderView.Interactive)

    # Set default widths based on column header text
    stretch_col = -1
    for col in range(col_count):
        header_text = (table.horizontalHeaderItem(col).text().lower()
                       if table.horizontalHeaderItem(col) else "")

        # Check if this is a stretch column
        if any(kw in header_text for kw in _STRETCH_KEYWORDS):
            stretch_col = col
            continue

        # Find best width from keywords
        width = None
        for keyword, w in _WIDTH_MAP.items():
            if keyword in header_text:
                width = w
                break

        if width:
            table.setColumnWidth(col, width)
        else:
            table.setColumnWidth(col, 120)

    # Set the stretch column (last resort: last column)
    if stretch_col >= 0:
        header.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    elif col_count > 0:
        header.setSectionResizeMode(col_count - 1, QHeaderView.Stretch)

    # Double-click on header edge auto-fits to content
    header.sectionDoubleClicked.connect(
        lambda idx: header.setSectionResizeMode(idx, QHeaderView.ResizeToContents)
    )

    # Enable mouse tracking for tooltips on hover
    table.setMouseTracking(True)

    # Horizontal scrollbar when columns exceed window width
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)


def set_item_with_tooltip(table: QTableWidget, row: int, col: int, item: QTableWidgetItem):
    """Set a table item and add its text as a tooltip for truncated content."""
    text = item.text()
    if text:
        item.setToolTip(text)
    table.setItem(row, col, item)
