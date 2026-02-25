"""Circular gauge widget with animated arc and needle."""

import math
from PySide6.QtCore import Qt, QRectF, QPointF, QTimer, Property
from PySide6.QtGui import (
    QPainter, QColor, QConicalGradient, QPen, QFont, QBrush,
    QRadialGradient, QPainterPath,
)
from PySide6.QtWidgets import QWidget


class CircularGauge(QWidget):
    """A professional circular gauge for displaying utilization metrics."""

    def __init__(self, title: str = "", unit: str = "", max_value: float = 100.0,
                 parent=None):
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._max_value = max_value
        self._current_value = 0.0
        self._display_value = 0.0  # smoothed value for animation
        self.setMinimumSize(180, 180)

        # Animation timer for smooth needle movement
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)  # ~60fps
        self._anim_timer.timeout.connect(self._animate_step)

    def set_value(self, value: float):
        self._current_value = min(max(value, 0), self._max_value)
        if not self._anim_timer.isActive():
            self._anim_timer.start()

    def _animate_step(self):
        diff = self._current_value - self._display_value
        if abs(diff) < 0.1:
            self._display_value = self._current_value
            self._anim_timer.stop()
        else:
            self._display_value += diff * 0.15
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        side = min(w, h)
        margin = side * 0.1
        rect = QRectF(
            (w - side) / 2 + margin,
            (h - side) / 2 + margin,
            side - 2 * margin,
            side - 2 * margin,
        )
        center = rect.center()
        radius = rect.width() / 2

        # Background circle
        bg_gradient = QRadialGradient(center, radius)
        bg_gradient.setColorAt(0, QColor("#313244"))
        bg_gradient.setColorAt(1, QColor("#1e1e2e"))
        painter.setBrush(QBrush(bg_gradient))
        painter.setPen(QPen(QColor("#45475a"), 2))
        painter.drawEllipse(rect)

        # Track arc (background arc)
        start_angle = 225  # degrees (bottom-left)
        span_angle = 270   # sweep 270 degrees clockwise
        pen = QPen(QColor("#45475a"), side * 0.04, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect.adjusted(8, 8, -8, -8), start_angle * 16, -span_angle * 16)

        # Value arc with gradient coloring
        fraction = self._display_value / self._max_value if self._max_value > 0 else 0
        value_span = span_angle * fraction

        # Color based on value: green → yellow → red
        if fraction < 0.5:
            arc_color = QColor("#a6e3a1")  # green
        elif fraction < 0.75:
            arc_color = QColor("#f9e2af")  # yellow
        else:
            arc_color = QColor("#f38ba8")  # red

        pen = QPen(arc_color, side * 0.04, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        inner = rect.adjusted(8, 8, -8, -8)
        painter.drawArc(inner, start_angle * 16, int(-value_span * 16))

        # Tick marks
        painter.setPen(QPen(QColor("#585b70"), 1))
        tick_count = 10
        for i in range(tick_count + 1):
            angle_deg = start_angle - (span_angle * i / tick_count)
            angle_rad = math.radians(angle_deg)
            inner_r = radius * 0.7
            outer_r = radius * 0.78
            x1 = center.x() + inner_r * math.cos(angle_rad)
            y1 = center.y() - inner_r * math.sin(angle_rad)
            x2 = center.x() + outer_r * math.cos(angle_rad)
            y2 = center.y() - outer_r * math.sin(angle_rad)
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Needle
        needle_angle_deg = start_angle - value_span
        needle_angle_rad = math.radians(needle_angle_deg)
        needle_len = radius * 0.55
        needle_tip = QPointF(
            center.x() + needle_len * math.cos(needle_angle_rad),
            center.y() - needle_len * math.sin(needle_angle_rad),
        )
        painter.setPen(QPen(QColor("#cdd6f4"), 2, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(center, needle_tip)

        # Center dot
        painter.setBrush(QBrush(QColor("#89b4fa")))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(center, 5, 5)

        # Value text
        font = QFont("Consolas", int(side * 0.1), QFont.Bold)
        painter.setFont(font)
        painter.setPen(QColor("#cdd6f4"))
        value_text = f"{self._display_value:.1f}"
        painter.drawText(
            QRectF(rect.left(), center.y() - side * 0.05, rect.width(), side * 0.15),
            Qt.AlignCenter, value_text,
        )

        # Unit text
        font = QFont("Consolas", int(side * 0.05))
        painter.setFont(font)
        painter.setPen(QColor("#a6adc8"))
        painter.drawText(
            QRectF(rect.left(), center.y() + side * 0.08, rect.width(), side * 0.1),
            Qt.AlignCenter, self._unit,
        )

        # Title text at bottom
        font = QFont("Segoe UI", int(side * 0.055))
        painter.setFont(font)
        painter.setPen(QColor("#a6adc8"))
        painter.drawText(
            QRectF(rect.left(), rect.bottom() - side * 0.05, rect.width(), side * 0.1),
            Qt.AlignCenter, self._title,
        )

        painter.end()
