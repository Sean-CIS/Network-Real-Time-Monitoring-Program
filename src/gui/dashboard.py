from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


# Threshold (in bytes/s) above which the dashboard chart switches to MB/s
_MB_THRESHOLD = 1_000_000


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Title
        title = QLabel("Network Monitor Dashboard")
        title.setStyleSheet("color: #cdd6f4; font-size: 18px; font-weight: bold; padding: 8px;")
        layout.addWidget(title)

        # Network info row
        net_cards_layout = QHBoxLayout()
        self._card_local_ip = StatCard("Local IP", "—")
        self._card_subnet = StatCard("Subnet", "—")
        self._card_download = StatCard("Download", "—")
        self._card_upload = StatCard("Upload", "—")
        self._card_latency = StatCard("Avg Latency", "—")
        self._card_devices = StatCard("Devices Online", "0")
        self._card_alerts = StatCard("Active Alerts", "0")
        net_cards_layout.addWidget(self._card_local_ip)
        net_cards_layout.addWidget(self._card_subnet)
        net_cards_layout.addWidget(self._card_download)
        net_cards_layout.addWidget(self._card_upload)
        net_cards_layout.addWidget(self._card_latency)
        net_cards_layout.addWidget(self._card_devices)
        net_cards_layout.addWidget(self._card_alerts)
        layout.addLayout(net_cards_layout)

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

        self._use_mb = False

    def update_network_info(self, local_ip: str, subnet: str):
        """Set the detected network info cards."""
        self._card_local_ip.set_value(local_ip)
        self._card_subnet.set_value(subnet)

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

        # Auto-scale chart between KB/s and MB/s
        peak = max(speed_down, speed_up)
        if peak >= _MB_THRESHOLD and not self._use_mb:
            self._use_mb = True
            self._bandwidth_chart.set_y_label("MB/s")
        elif peak < _MB_THRESHOLD and self._use_mb:
            self._use_mb = False
            self._bandwidth_chart.set_y_label("KB/s")

        if self._use_mb:
            self._bandwidth_chart.add_data_point(
                [speed_down / 1_000_000, speed_up / 1_000_000]
            )
        else:
            self._bandwidth_chart.add_data_point(
                [speed_down / 1_000, speed_up / 1_000]
            )

    def update_latency_summary(self, avg_ms: float):
        self._card_latency.set_value(f"{avg_ms:.1f} ms")
        self._latency_chart.add_data_point([avg_ms])

    def update_device_count(self, online: int):
        self._card_devices.set_value(str(online))

    def update_alert_count(self, count: int):
        self._card_alerts.set_value(str(count))
