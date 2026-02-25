"""Ring/donut chart widget with animated segments."""

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from src.gui import theme


class RingChart(QWidget):
    """Hollow donut chart with animated segment sweep and center label."""

    def __init__(self, title: str = "", ring_width: int = 18, parent=None):
        super().__init__(parent)
        self._title = title
        self._ring_width = ring_width
        self._segments: list[tuple[str, int, QColor]] = []
        self._progress = 0.0
        self._anim = None
        self.setMinimumHeight(120)
        self.setMaximumHeight(160)

    def _get_progress(self) -> float:
        return self._progress

    def _set_progress(self, val: float):
        self._progress = val
        self.update()

    animProgress = Property(float, _get_progress, _set_progress)

    def set_data(self, data: dict[str, int]):
        sorted_items = sorted(data.items(), key=lambda x: -x[1])
        self._segments = [
            (k, v, theme.PIE_COLORS[i % len(theme.PIE_COLORS)])
            for i, (k, v) in enumerate(sorted_items[:10])
        ]
        self._anim = QPropertyAnimation(self, b"animProgress")
        self._anim.setDuration(600)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.start()

    def paintEvent(self, event):
        if not self._segments:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        h = self.height()
        ring_size = min(h - 10, 130)
        rw = self._ring_width
        inset = rw // 2
        x = 10 + inset
        y = (h - ring_size) // 2 + inset
        diameter = ring_size - rw

        total = sum(s[1] for s in self._segments)
        if total == 0:
            painter.end()
            return

        # Draw ring segments
        start_angle = 90 * 16  # start at top
        for name, count, color in self._segments:
            span = int(count / total * 360 * 16 * self._progress)
            pen = QPen(color, rw)
            pen.setCapStyle(Qt.FlatCap)
            painter.setPen(pen)
            painter.drawArc(x, y, diameter, diameter, start_angle, -span)
            start_angle -= span

        # Center text — total count
        painter.setPen(QColor(theme.GREEN))
        center_font = QFont("Courier New", 16, QFont.Bold)
        painter.setFont(center_font)
        center_x = x + diameter // 2
        center_y = y + diameter // 2
        text = str(total)
        fm = painter.fontMetrics()
        tw = fm.horizontalAdvance(text)
        th = fm.height()
        painter.drawText(center_x - tw // 2, center_y + th // 4, text)

        # Title below center
        if self._title:
            title_font = QFont("Courier New", 7)
            painter.setFont(title_font)
            painter.setPen(QColor(theme.GREEN_MUTED))
            tfm = painter.fontMetrics()
            ttw = tfm.horizontalAdvance(self._title)
            painter.drawText(center_x - ttw // 2, center_y + th // 4 + 14, self._title)

        # Legend to the right
        legend_x = x + diameter + rw + 15
        legend_y = 10
        painter.setPen(QColor(theme.GREEN))
        legend_font = QFont("Courier New", 8)
        painter.setFont(legend_font)
        for i, (name, count, color) in enumerate(self._segments[:8]):
            pct = count / total * 100
            painter.fillRect(legend_x, legend_y + i * 17, 10, 10, color)
            painter.drawText(
                legend_x + 14, legend_y + i * 17 + 10,
                f"{name}: {count} ({pct:.0f}%)"
            )

        painter.end()
