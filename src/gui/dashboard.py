from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Title
        title = QLabel("Network Monitor Dashboard")
        title.setStyleSheet("color: #cdd6f4; font-size: 18px; font-weight: bold; padding: 8px;")
        layout.addWidget(title)

        # Top stat cards row
        cards_layout = QHBoxLayout()
        self._card_download = StatCard("Download", "—")
        self._card_upload = StatCard("Upload", "—")
        self._card_latency = StatCard("Avg Latency", "—")
        self._card_devices = StatCard("Devices Online", "0")
        self._card_alerts = StatCard("Active Alerts", "0")
        cards_layout.addWidget(self._card_download)
        cards_layout.addWidget(self._card_upload)
        cards_layout.addWidget(self._card_latency)
        cards_layout.addWidget(self._card_devices)
        cards_layout.addWidget(self._card_alerts)
        layout.addLayout(cards_layout)

        # Charts row
        charts_layout = QHBoxLayout()
        self._bandwidth_chart = LiveChart(
            title="Bandwidth",
            y_label="KB/s",
            num_lines=2,
            line_labels=["Down", "Up"],
            max_points=120,
        )
        self._latency_chart = LiveChart(
            title="Latency",
            y_label="ms",
            num_lines=1,
            line_labels=["Avg"],
            max_points=120,
        )
        charts_layout.addWidget(self._bandwidth_chart)
        charts_layout.addWidget(self._latency_chart)
        layout.addLayout(charts_layout, stretch=1)

    def update_bandwidth_summary(self, speed_down: float, speed_up: float):
        if speed_down >= 1_000_000:
            self._card_download.set_value(f"{speed_down / 1_000_000:.2f} MB/s")
        elif speed_down >= 1_000:
            self._card_download.set_value(f"{speed_down / 1_000:.1f} KB/s")
        else:
            self._card_download.set_value(f"{speed_down:.0f} B/s")

        if speed_up >= 1_000_000:
            self._card_upload.set_value(f"{speed_up / 1_000_000:.2f} MB/s")
        elif speed_up >= 1_000:
            self._card_upload.set_value(f"{speed_up / 1_000:.1f} KB/s")
        else:
            self._card_upload.set_value(f"{speed_up:.0f} B/s")

        self._bandwidth_chart.add_data_point([speed_down / 1000, speed_up / 1000])

    def update_latency_summary(self, avg_ms: float):
        self._card_latency.set_value(f"{avg_ms:.1f} ms")
        self._latency_chart.add_data_point([avg_ms])

    def update_device_count(self, online: int):
        self._card_devices.set_value(str(online))

    def update_alert_count(self, count: int):
        self._card_alerts.set_value(str(count))
