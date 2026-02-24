from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard
from src.gui.widgets.traffic_heatmap import TrafficHeatmap


# Threshold (in bytes/s) above which the dashboard chart switches to MB/s
_MB_THRESHOLD = 1_000_000


class SecurityTimeline(QWidget):
    """Mini bar chart showing security events per hour over the last 24 hours."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(60)
        self.setMaximumHeight(80)
        self._hourly_data: list[dict] = []  # [{hour, critical, warning, info}]

    def set_data(self, hourly: list[dict]):
        self._hourly_data = hourly
        self.update()

    def paintEvent(self, event):
        if not self._hourly_data:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        bar_w = max(2, (w - 48) // 24)
        max_count = max(
            (d.get("critical", 0) + d.get("warning", 0) + d.get("info", 0))
            for d in self._hourly_data
        ) or 1

        x_offset = 24
        for i, d in enumerate(self._hourly_data):
            total = d.get("critical", 0) + d.get("warning", 0) + d.get("info", 0)
            bar_h = max(1, int((total / max_count) * (h - 20))) if total > 0 else 0

            if d.get("critical", 0) > 0:
                color = QColor("#f38ba8")
            elif d.get("warning", 0) > 0:
                color = QColor("#f9e2af")
            else:
                color = QColor("#94e2d5")

            painter.fillRect(
                x_offset + i * bar_w, h - 15 - bar_h,
                bar_w - 1, bar_h,
                color,
            )

        # Draw hour labels every 6 hours
        painter.setPen(QColor("#a6adc8"))
        for i, d in enumerate(self._hourly_data):
            hr = d.get("hour", i)
            if hr % 6 == 0:
                painter.drawText(
                    x_offset + i * bar_w - 5, h - 2,
                    f"{hr:02d}"
                )
        painter.end()


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Title row with baseline mode indicator
        title_row = QHBoxLayout()
        title = QLabel("Network Monitor Dashboard")
        title.setStyleSheet(
            "color: #cdd6f4; font-size: 18px; font-weight: bold; padding: 8px;"
        )
        title_row.addWidget(title)

        self._baseline_indicator = QLabel("")
        self._baseline_indicator.setStyleSheet(
            "color: #f9e2af; font-size: 12px; padding: 8px;"
        )
        title_row.addWidget(self._baseline_indicator)
        title_row.addStretch()
        layout.addLayout(title_row)

        # Network info row
        net_cards_layout = QHBoxLayout()
        self._card_local_ip = StatCard("Local IP", "\u2014")
        self._card_subnet = StatCard("Subnet", "\u2014")
        self._card_download = StatCard("Download", "\u2014")
        self._card_upload = StatCard("Upload", "\u2014")
        self._card_latency = StatCard("Avg Latency", "\u2014")
        self._card_devices = StatCard("Devices Online", "0")
        self._card_alerts = StatCard("Active Alerts", "0")
        self._card_security_score = StatCard("Security Score", "\u2014")
        net_cards_layout.addWidget(self._card_local_ip)
        net_cards_layout.addWidget(self._card_subnet)
        net_cards_layout.addWidget(self._card_download)
        net_cards_layout.addWidget(self._card_upload)
        net_cards_layout.addWidget(self._card_latency)
        net_cards_layout.addWidget(self._card_devices)
        net_cards_layout.addWidget(self._card_alerts)
        net_cards_layout.addWidget(self._card_security_score)
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

        # Security timeline
        timeline_label = QLabel("Last 24h Security Events")
        timeline_label.setStyleSheet(
            "color: #cdd6f4; font-size: 13px; font-weight: bold; padding: 4px 0 0 0;"
        )
        layout.addWidget(timeline_label)
        self._security_timeline = SecurityTimeline()
        layout.addWidget(self._security_timeline)

        # Traffic heatmap
        self._traffic_heatmap = TrafficHeatmap()
        layout.addWidget(self._traffic_heatmap)

        self._use_mb = False

    def update_network_info(self, local_ip: str, subnet: str):
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

    def update_security_score(self, score: int):
        self._card_security_score.set_value(str(score))
        if score >= 80:
            color = "#a6e3a1"  # green
        elif score >= 50:
            color = "#f9e2af"  # yellow
        else:
            color = "#f38ba8"  # red
        for child in self._card_security_score.findChildren(QLabel):
            if child.text() == str(score):
                child.setStyleSheet(
                    f"color: {color}; font-size: 20px; font-weight: bold;"
                )
                break

    def update_security_timeline(self, hourly_data: list[dict]):
        self._security_timeline.set_data(hourly_data)

    def update_traffic_heatmap(self, heatmap_data: list[dict]):
        self._traffic_heatmap.set_data(heatmap_data)

    def update_baseline_mode(self, mode: str):
        if mode == "learning":
            self._baseline_indicator.setText("Baseline: Learning Mode")
            self._baseline_indicator.setStyleSheet(
                "color: #f9e2af; font-size: 12px; padding: 8px;"
            )
        elif mode == "monitoring":
            self._baseline_indicator.setText("Baseline: Monitoring Mode")
            self._baseline_indicator.setStyleSheet(
                "color: #a6e3a1; font-size: 12px; padding: 8px;"
            )
        else:
            self._baseline_indicator.setText("")
