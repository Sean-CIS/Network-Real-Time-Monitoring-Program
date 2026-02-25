"""Radial arc gauge widget — semi-circular with animated needle."""

import math

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QObject,
    QPropertyAnimation,
    Qt,
)
from PySide6.QtGui import QColor, QConicalGradient, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QWidget

from PySide6.QtCore import QPointF

from src.gui import theme


class RadialGauge(QWidget):
    """Semi-circular arc gauge with animated needle and gradient fill."""

    def __init__(self, title: str = "", min_val: float = 0, max_val: float = 100,
                 unit: str = "", thresholds: tuple = (60, 80),
                 invert: bool = False, parent=None):
        super().__init__(parent)
        self._title = title
        self._min_val = min_val
        self._max_val = max_val
        self._unit = unit
        self._thresholds = thresholds  # (amber_start_pct, red_start_pct)
        self._invert = invert  # if True, low=red high=green
        self._display_value = min_val
        self._current_angle = 0.0
        self._anim = None
        self.setMinimumSize(180, 130)

    def _get_angle(self) -> float:
        return self._current_angle

    def _set_angle(self, val: float):
        self._current_angle = val
        self.update()

    angle = Property(float, _get_angle, _set_angle)

    def _value_to_angle(self, value: float) -> float:
        """Map value to angle (0=left, 180=right in our drawing)."""
        ratio = (value - self._min_val) / max(self._max_val - self._min_val, 0.001)
        ratio = max(0.0, min(1.0, ratio))
        return ratio * 180.0

    def set_value(self, value: float):
        value = max(self._min_val, min(self._max_val, value))
        self._display_value = value
        target = self._value_to_angle(value)
        self._anim = QPropertyAnimation(self, b"angle")
        self._anim.setDuration(400)
        self._anim.setStartValue(self._current_angle)
        self._anim.setEndValue(target)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.start()

    def _value_color(self) -> QColor:
        """Return color for the current value based on thresholds."""
        ratio = (self._display_value - self._min_val) / max(
            self._max_val - self._min_val, 0.001
        )
        pct = ratio * 100
        if self._invert:
            pct = 100 - pct
        if pct >= self._thresholds[1]:
            return QColor(theme.GREEN)
        elif pct >= self._thresholds[0]:
            return QColor(theme.AMBER)
        else:
            return QColor(theme.RED)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        cx = w / 2
        cy = h * 0.65  # center of the arc (lower half)

        radius = min(w / 2 - 15, h * 0.55)
        arc_width = 10
        rect_size = radius * 2
        arc_rect_x = cx - radius
        arc_rect_y = cy - radius

        # Background arc — gradient from green to amber to red
        gradient = QConicalGradient(cx, cy, 180)
        if self._invert:
            gradient.setColorAt(0.0, QColor(theme.RED))
            gradient.setColorAt(0.4, QColor(theme.AMBER))
            gradient.setColorAt(1.0, QColor(theme.GREEN))
        else:
            gradient.setColorAt(0.0, QColor(theme.GREEN))
            gradient.setColorAt(0.4, QColor(theme.AMBER))
            gradient.setColorAt(1.0, QColor(theme.RED))

        pen = QPen()
        pen.setWidth(arc_width)
        pen.setBrush(gradient)
        pen.setCapStyle(Qt.FlatCap)
        painter.setPen(pen)
        # Draw 180° arc from 180° to 0° (left to right, top half)
        painter.drawArc(
            int(arc_rect_x), int(arc_rect_y), int(rect_size), int(rect_size),
            0 * 16, 180 * 16
        )

        # Tick marks
        painter.setPen(QPen(QColor(theme.GREEN_MUTED), 1))
        tick_font = QFont("Courier New", 7)
        painter.setFont(tick_font)
        for i in range(11):
            angle_deg = 180 - i * 18  # 180 to 0
            angle_rad = math.radians(angle_deg)
            inner_r = radius - arc_width / 2 - 3
            outer_r = radius - arc_width / 2 - 10
            x1 = cx + inner_r * math.cos(angle_rad)
            y1 = cy - inner_r * math.sin(angle_rad)
            x2 = cx + outer_r * math.cos(angle_rad)
            y2 = cy - outer_r * math.sin(angle_rad)
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))

            # Labels at 0, 25, 50, 75, 100%
            if i % 5 == 0:
                val = self._min_val + (self._max_val - self._min_val) * i / 10
                label_r = outer_r - 10
                lx = cx + label_r * math.cos(angle_rad) - 10
                ly = cy - label_r * math.sin(angle_rad) + 4
                painter.drawText(int(lx), int(ly), f"{val:.0f}")

        # Needle
        angle_rad = math.radians(180 - self._current_angle)
        needle_len = radius - arc_width / 2 - 5
        tip_x = cx + needle_len * math.cos(angle_rad)
        tip_y = cy - needle_len * math.sin(angle_rad)

        # Needle triangle
        perp_rad = angle_rad + math.pi / 2
        base_offset = 3
        bx1 = cx + base_offset * math.cos(perp_rad)
        by1 = cy - base_offset * math.sin(perp_rad)
        bx2 = cx - base_offset * math.cos(perp_rad)
        by2 = cy + base_offset * math.sin(perp_rad)

        needle = QPolygonF([
            QPointF(bx1, by1),
            QPointF(tip_x, tip_y),
            QPointF(bx2, by2),
        ])
        painter.setPen(Qt.NoPen)
        painter.setBrush(self._value_color())
        painter.drawPolygon(needle)

        # Center dot
        painter.setBrush(QColor(theme.GREEN))
        painter.drawEllipse(QPointF(cx, cy), 4, 4)

        # Value text
        val_font = QFont("Courier New", 18, QFont.Bold)
        painter.setFont(val_font)
        painter.setPen(self._value_color())
        val_text = f"{self._display_value:.0f}"
        if self._unit:
            val_text += self._unit
        fm = painter.fontMetrics()
        tw = fm.horizontalAdvance(val_text)
        painter.drawText(int(cx - tw / 2), int(cy + 20), val_text)

        # Title
        title_font = QFont("Courier New", 8, QFont.Bold)
        painter.setFont(title_font)
        painter.setPen(QColor(theme.GREEN_MUTED))
        tfm = painter.fontMetrics()
        ttw = tfm.horizontalAdvance(self._title)
        painter.drawText(int(cx - ttw / 2), int(cy + 34), self._title)

        painter.end()
