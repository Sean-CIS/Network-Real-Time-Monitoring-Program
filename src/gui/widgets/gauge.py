"""Circular gauge widget with animated arc, glow, and needle."""

import math
from PySide6.QtCore import Qt, QRectF, QPointF, QTimer
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
        self._raw_bytes = 0.0     # raw byte value for KB/s display
        self.setMinimumSize(180, 180)

        # Animation timer for smooth needle movement
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)  # ~60fps
        self._anim_timer.timeout.connect(self._animate_step)

    def set_value(self, value: float, raw_bytes: float = 0.0):
        self._current_value = min(max(value, 0), self._max_value)
        self._raw_bytes = raw_bytes
        if not self._anim_timer.isActive():
            self._anim_timer.start()

    def _animate_step(self):
        diff = self._current_value - self._display_value
        if abs(diff) < 0.01:
            self._display_value = self._current_value
            self._anim_timer.stop()
        else:
            self._display_value += diff * 0.15
        self.update()

    def _get_arc_color(self, fraction: float) -> QColor:
        """Interpolate green (#00ff41) -> amber (#ffb000) -> red (#ff3333)."""
        if fraction <= 0.5:
            t = fraction / 0.5
            r = int(0x00 + (0xff - 0x00) * t)
            g = int(0xff + (0xb0 - 0xff) * t)
            b = int(0x41 + (0x00 - 0x41) * t)
        else:
            t = (fraction - 0.5) / 0.5
            r = int(0xff + (0xff - 0xff) * t)
            g = int(0xb0 + (0x33 - 0xb0) * t)
            b = int(0x00 + (0x33 - 0x00) * t)
        return QColor(min(r, 255), min(g, 255), min(b, 255))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

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

        # Background circle with subtle gradient
        bg_gradient = QRadialGradient(center, radius)
        bg_gradient.setColorAt(0, QColor(55, 55, 75))
        bg_gradient.setColorAt(0.7, QColor(40, 40, 58))
        bg_gradient.setColorAt(1, QColor(30, 30, 46))
        painter.setBrush(QBrush(bg_gradient))
        painter.setPen(QPen(QColor("#45475a"), 2))
        painter.drawEllipse(rect)

        # Track arc (background arc)
        start_angle = 225  # degrees (bottom-left)
        span_angle = 270   # sweep 270 degrees clockwise
        arc_rect = rect.adjusted(8, 8, -8, -8)
        pen = QPen(QColor("#45475a"), side * 0.04, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(arc_rect, start_angle * 16, -span_angle * 16)

        # Value arc with gradient coloring
        fraction = self._display_value / self._max_value if self._max_value > 0 else 0
        fraction = min(fraction, 1.0)
        value_span = span_angle * fraction
        arc_color = self._get_arc_color(fraction)

        if value_span > 0.5:
            # Glow pass: wider, semi-transparent
            glow_color = QColor(arc_color)
            glow_color.setAlpha(77)  # ~30% opacity
            pen = QPen(glow_color, 14, Qt.SolidLine, Qt.RoundCap)
            painter.setPen(pen)
            painter.drawArc(arc_rect, start_angle * 16, int(-value_span * 16))

            # Sharp pass on top
            pen = QPen(arc_color, 4, Qt.SolidLine, Qt.RoundCap)
            painter.setPen(pen)
            painter.drawArc(arc_rect, start_angle * 16, int(-value_span * 16))

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

        # Needle — thin white line
        needle_angle_deg = start_angle - value_span
        needle_angle_rad = math.radians(needle_angle_deg)
        needle_len = radius * 0.55
        needle_tip = QPointF(
            center.x() + needle_len * math.cos(needle_angle_rad),
            center.y() - needle_len * math.sin(needle_angle_rad),
        )
        painter.setPen(QPen(QColor(255, 255, 255), 1.5, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(center, needle_tip)

        # Center pivot dot (small white circle)
        painter.setBrush(QBrush(QColor(255, 255, 255)))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(center, 4, 4)

        # Value text — 32pt bold, Consolas/Courier New for correct decimal rendering
        value_size = max(int(side * 0.14), 12)
        font = QFont()
        font.setFamilies(["Consolas", "Courier New", "monospace"])
        font.setPixelSize(value_size)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#cdd6f4"))

        # Format value: KB/s when unit is MB/s and value < 1
        display_val = self._display_value
        display_unit = self._unit
        if self._unit == "MB/s" and display_val < 1.0 and self._raw_bytes > 0:
            kb_val = self._raw_bytes / 1000.0
            value_text = f"{kb_val:.1f}"
            display_unit = "KB/s"
        else:
            value_text = f"{display_val:.1f}"

        painter.drawText(
            QRectF(rect.left(), center.y() - side * 0.08, rect.width(), side * 0.16),
            Qt.AlignCenter, value_text,
        )

        # Unit label — 12pt below value
        unit_size = max(int(side * 0.06), 8)
        font2 = QFont()
        font2.setFamilies(["Consolas", "Courier New", "monospace"])
        font2.setPixelSize(unit_size)
        painter.setFont(font2)
        painter.setPen(QColor("#a6adc8"))
        painter.drawText(
            QRectF(rect.left(), center.y() + side * 0.08, rect.width(), side * 0.1),
            Qt.AlignCenter, display_unit,
        )

        # Title text at bottom
        title_size = max(int(side * 0.055), 8)
        font3 = QFont()
        font3.setFamilies(["Segoe UI", "Consolas", "monospace"])
        font3.setPixelSize(title_size)
        painter.setFont(font3)
        painter.setPen(QColor("#a6adc8"))
        painter.drawText(
            QRectF(rect.left(), rect.bottom() - side * 0.05, rect.width(), side * 0.1),
            Qt.AlignCenter, self._title,
        )

        painter.end()
