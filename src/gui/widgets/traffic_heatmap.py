"""Traffic heatmap widget showing hourly bandwidth by day of week — CRT theme."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QFont
from PySide6.QtWidgets import QWidget

from src.gui import theme


_DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def _intensity_color(value: float, max_val: float) -> QColor:
    """Map a value to a CRT color gradient: dark -> green -> amber -> red."""
    if max_val <= 0 or value <= 0:
        return QColor(theme.BG_PRIMARY)

    ratio = min(value / max_val, 1.0)
    if ratio < 0.33:
        # Dark green to phosphor green
        t = ratio / 0.33
        r = int(5 * (1 - t) + 0 * t)
        g = int(15 * (1 - t) + 255 * t)
        b = int(5 * (1 - t) + 65 * t)
    elif ratio < 0.66:
        # Phosphor green to amber
        t = (ratio - 0.33) / 0.33
        r = int(0 * (1 - t) + 255 * t)
        g = int(255 * (1 - t) + 176 * t)
        b = int(65 * (1 - t) + 0 * t)
    else:
        # Amber to red
        t = (ratio - 0.66) / 0.34
        r = int(255 * (1 - t) + 255 * t)
        g = int(176 * (1 - t) + 51 * t)
        b = int(0 * (1 - t) + 51 * t)

    return QColor(r, g, b)


class TrafficHeatmap(QWidget):
    """24x7 grid showing hourly traffic intensity by day of week."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(120)
        self.setMaximumHeight(160)
        # data[dow][hour] = avg_bps  (dow: 0=Sun, 6=Sat)
        self._data: dict[int, dict[int, float]] = {}
        self._max_val: float = 0

    def set_data(self, heatmap_data: list[dict]):
        """Accept data from db.get_bandwidth_heatmap_data().

        Each dict: {"dow": int, "hour": int, "avg_bps": float}
        """
        self._data.clear()
        self._max_val = 0
        for row in heatmap_data:
            dow = row.get("dow", 0)
            hour = row.get("hour", 0)
            avg = row.get("avg_bps", 0) or 0
            if dow not in self._data:
                self._data[dow] = {}
            self._data[dow][hour] = avg
            if avg > self._max_val:
                self._max_val = avg
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        left_margin = 35
        top_margin = 18
        bottom_margin = 18

        grid_w = w - left_margin - 10
        grid_h = h - top_margin - bottom_margin
        cell_w = max(2, grid_w // 24)
        cell_h = max(2, grid_h // 7)

        # Draw title
        painter.setPen(QColor(theme.GREEN))
        painter.setFont(QFont("Courier New", 10, QFont.Bold))
        painter.drawText(left_margin, 14, "7-Day Traffic Heatmap")
        painter.setFont(QFont("Courier New", 8))

        # Draw cells
        for dow in range(7):
            for hour in range(24):
                val = self._data.get(dow, {}).get(hour, 0)
                color = _intensity_color(val, self._max_val)
                x = left_margin + hour * cell_w
                y = top_margin + dow * cell_h
                painter.fillRect(x, y, cell_w - 1, cell_h - 1, color)

        # Day labels
        painter.setPen(QColor(theme.GREEN_MUTED))
        for dow in range(7):
            y = top_margin + dow * cell_h + cell_h // 2 + 4
            painter.drawText(2, y, _DAY_LABELS[dow])

        # Hour labels (every 3 hours)
        for hour in range(0, 24, 3):
            x = left_margin + hour * cell_w
            painter.drawText(x, h - 4, f"{hour:02d}")

        painter.end()
