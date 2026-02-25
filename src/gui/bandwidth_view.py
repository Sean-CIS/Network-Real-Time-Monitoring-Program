from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


def _format_speed(bytes_per_sec: float) -> str:
    if bytes_per_sec >= 1_000_000:
        return f"{bytes_per_sec / 1_000_000:.2f} MB/s"
    elif bytes_per_sec >= 1_000:
        return f"{bytes_per_sec / 1_000:.1f} KB/s"
    return f"{bytes_per_sec:.0f} B/s"


def _format_bytes(total_bytes: int) -> str:
    if total_bytes >= 1_000_000_000:
        return f"{total_bytes / 1_000_000_000:.2f} GB"
    elif total_bytes >= 1_000_000:
        return f"{total_bytes / 1_000_000:.1f} MB"
    elif total_bytes >= 1_000:
        return f"{total_bytes / 1_000:.1f} KB"
    return f"{total_bytes} B"


_MB_THRESHOLD = 1_000_000


class UtilizationBar(QWidget):
    """Horizontal bar showing bandwidth utilization percentage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(18)
        self.setMaximumHeight(22)
        self._pct = 0.0
        self._label = ""

    def set_value(self, pct: float, label: str = ""):
        self._pct = max(0.0, min(100.0, pct))
        self._label = label
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        h = self.height()

        painter.fillRect(0, 0, w, h, QColor(theme.BG_SURFACE))
        painter.setPen(QColor(theme.BORDER))
        painter.drawRect(0, 0, w - 1, h - 1)

        fill_w = int(w * self._pct / 100)
        if self._pct > 80:
            color = QColor(theme.RED)
        elif self._pct > 50:
            color = QColor(theme.AMBER)
        else:
            color = QColor(theme.GREEN)
        color.setAlpha(180)
        painter.fillRect(1, 1, fill_w - 2, h - 2, color)

        painter.setPen(QColor(theme.GREEN))
        text = self._label or f"{self._pct:.1f}%"
        painter.drawText(4, h - 5, text)
        painter.end()


class BandwidthView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # Header
        header = QHBoxLayout()
        title = QLabel("[ BANDWIDTH MONITOR ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(QLabel("Interface:"))
        self._interface_combo = QComboBox()
        self._interface_combo.setMinimumWidth(200)
        self._interface_combo.currentTextChanged.connect(self._on_interface_changed)
        header.addWidget(self._interface_combo)
        layout.addLayout(header)

        # Utilization bar
        util_row = QHBoxLayout()
        util_label = QLabel("UTILIZATION")
        util_label.setStyleSheet(theme.SECTION_LABEL)
        util_row.addWidget(util_label)
        self._util_bar = UtilizationBar()
        util_row.addWidget(self._util_bar, stretch=1)
        layout.addLayout(util_row)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_download = StatCard("Download Speed", "\u2014", sparkline=True)
        self._card_upload = StatCard("Upload Speed", "\u2014", sparkline=True)
        self._card_total_down = StatCard("Total Downloaded", "\u2014")
        self._card_total_up = StatCard("Total Uploaded", "\u2014")
        cards_layout.addWidget(self._card_download)
        cards_layout.addWidget(self._card_upload)
        cards_layout.addWidget(self._card_total_down)
        cards_layout.addWidget(self._card_total_up)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Speed chart
        self._speed_chart = LiveChart(
            title="Bandwidth Speed",
            y_label="Speed (KB/s)",
            num_lines=2,
            line_labels=["Download", "Upload"],
            max_points=300,
        )
        layout.addWidget(self._speed_chart, stretch=1)

        self._current_interface: str = ""
        self._all_data: dict[str, dict] = {}
        self._use_mb = False

    def set_interfaces(self, interfaces: list[str]):
        current = self._interface_combo.currentText()
        self._interface_combo.blockSignals(True)
        self._interface_combo.clear()
        self._interface_combo.addItems(interfaces)
        if current in interfaces:
            self._interface_combo.setCurrentText(current)
        self._interface_combo.blockSignals(False)
        if not self._current_interface and interfaces:
            self._current_interface = interfaces[0]

    def update_bandwidth(self, data: dict):
        self._all_data = data
        interfaces = list(data.keys())
        if interfaces and self._interface_combo.count() == 0:
            self.set_interfaces(interfaces)

        iface = self._interface_combo.currentText()
        if iface and iface in data:
            d = data[iface]
            speed_down = d.get("speed_down", 0)
            speed_up = d.get("speed_up", 0)

            self._card_download.set_value(_format_speed(speed_down))
            self._card_download.add_spark_point(speed_down / 1000)
            self._card_upload.set_value(_format_speed(speed_up))
            self._card_upload.add_spark_point(speed_up / 1000)
            self._card_total_down.set_value(_format_bytes(d.get("bytes_recv", 0)))
            self._card_total_up.set_value(_format_bytes(d.get("bytes_sent", 0)))

            # Utilization bar
            total_bps = (speed_down + speed_up) * 8
            util_pct = min(100.0, total_bps / 1_000_000_000 * 100)
            self._util_bar.set_value(
                util_pct,
                f"{_format_speed(speed_down)} \u2193  {_format_speed(speed_up)} \u2191  ({util_pct:.1f}%)"
            )

            # Auto-scale
            peak = max(speed_down, speed_up)
            if peak >= _MB_THRESHOLD and not self._use_mb:
                self._use_mb = True
                self._speed_chart.set_y_label("Speed (MB/s)")
            elif peak < _MB_THRESHOLD and self._use_mb:
                self._use_mb = False
                self._speed_chart.set_y_label("Speed (KB/s)")

            if self._use_mb:
                self._speed_chart.add_data_point(
                    [speed_down / 1_000_000, speed_up / 1_000_000]
                )
            else:
                self._speed_chart.add_data_point(
                    [speed_down / 1_000, speed_up / 1_000]
                )

    def _on_interface_changed(self, interface: str):
        self._current_interface = interface
        self._use_mb = False
        self._speed_chart.set_y_label("Speed (KB/s)")
        self._speed_chart.clear_data()
