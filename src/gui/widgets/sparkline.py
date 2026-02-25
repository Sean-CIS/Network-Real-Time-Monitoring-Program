"""Tiny inline sparkline chart widget for embedding in stat cards."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from src.gui import theme


class Sparkline(QWidget):
    """Minimal trend line chart — no axes, no labels, just the line."""

    def __init__(self, max_points: int = 30, color: str = theme.GREEN,
                 invert_trend: bool = False, parent=None):
        super().__init__(parent)
        self.setFixedHeight(20)
        self.setMinimumWidth(60)
        self._data: list[float] = []
        self._max_points = max_points
        self._base_color = color
        self._invert_trend = invert_trend  # True = down is good (latency)

    def add_point(self, value: float):
        self._data.append(value)
        if len(self._data) > self._max_points:
            self._data = self._data[-self._max_points:]
        self.update()

    def _trend_color(self) -> QColor:
        if len(self._data) < 5:
            return QColor(self._base_color)
        recent = self._data[-5:]
        going_up = recent[-1] > recent[0]
        if self._invert_trend:
            going_up = not going_up
        return QColor(theme.GREEN) if going_up else QColor(theme.RED)

    def paintEvent(self, event):
        if len(self._data) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        padding = 2

        data_min = min(self._data)
        data_max = max(self._data)
        data_range = data_max - data_min if data_max != data_min else 1.0

        n = len(self._data)
        step_x = (w - 2 * padding) / max(n - 1, 1)

        color = self._trend_color()

        # Build path
        path = QPainterPath()
        points = []
        for i, val in enumerate(self._data):
            x = padding + i * step_x
            y = h - padding - ((val - data_min) / data_range) * (h - 2 * padding)
            points.append((x, y))
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        # Fill below line
        fill_path = QPainterPath(path)
        fill_path.lineTo(points[-1][0], h)
        fill_path.lineTo(points[0][0], h)
        fill_path.closeSubpath()
        fill_color = QColor(color)
        fill_color.setAlpha(25)
        painter.fillPath(fill_path, fill_color)

        # Stroke line
        painter.setPen(QPen(color, 1.5))
        painter.drawPath(path)

        # Dot at last point
        last_x, last_y = points[-1]
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(int(last_x) - 2, int(last_y) - 2, 4, 4)

        painter.end()
