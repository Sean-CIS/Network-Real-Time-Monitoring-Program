from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

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


# Threshold (in bytes/s) above which the chart switches from KB/s to MB/s
_MB_THRESHOLD = 1_000_000  # 1 MB/s


class BandwidthView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Header with interface selector
        header = QHBoxLayout()
        header.addWidget(QLabel("Interface:"))
        self._interface_combo = QComboBox()
        self._interface_combo.setMinimumWidth(200)
        self._interface_combo.currentTextChanged.connect(self._on_interface_changed)
        header.addWidget(self._interface_combo)
        header.addStretch()
        layout.addLayout(header)

        # Stat cards row
        cards_layout = QHBoxLayout()
        self._card_download = StatCard("Download Speed", "—")
        self._card_upload = StatCard("Upload Speed", "—")
        self._card_total_down = StatCard("Total Downloaded", "—")
        self._card_total_up = StatCard("Total Uploaded", "—")
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
        """Called with data = {interface: {speed_up, speed_down, bytes_sent, bytes_recv}}"""
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
            self._card_upload.set_value(_format_speed(speed_up))
            self._card_total_down.set_value(_format_bytes(d.get("bytes_recv", 0)))
            self._card_total_up.set_value(_format_bytes(d.get("bytes_sent", 0)))

            # Auto-scale: switch between KB/s and MB/s
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
