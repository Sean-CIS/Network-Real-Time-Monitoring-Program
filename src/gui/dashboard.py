from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from src.gui import theme
from src.gui.widgets.gauge import RadialGauge
from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.ring_chart import RingChart
from src.gui.widgets.stat_card import StatCard
from src.gui.widgets.topology_map import TopologyMapWidget
from src.gui.widgets.traffic_heatmap import TrafficHeatmap
from src.gui.widgets.world_map import WorldMapWidget


# Threshold (in bytes/s) above which the dashboard chart switches to MB/s
_MB_THRESHOLD = 1_000_000


class SecurityTimeline(QWidget):
    """Mini bar chart showing security events per hour over the last 24 hours."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(60)
        self.setMaximumHeight(80)
        self._hourly_data: list[dict] = []

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
                color = QColor(theme.RED)
            elif d.get("warning", 0) > 0:
                color = QColor(theme.AMBER)
            else:
                color = QColor(theme.GREEN)

            painter.fillRect(
                x_offset + i * bar_w, h - 15 - bar_h,
                bar_w - 1, bar_h,
                color,
            )

        painter.setPen(QColor(theme.GREEN_MUTED))
        for i, d in enumerate(self._hourly_data):
            hr = d.get("hour", i)
            if hr % 6 == 0:
                painter.drawText(
                    x_offset + i * bar_w - 5, h - 2,
                    f"{hr:02d}"
                )
        painter.end()


def _make_separator():
    sep = QFrame()
    sep.setFrameShape(QFrame.HLine)
    sep.setStyleSheet(f"background-color: {theme.GREEN_DARK}; max-height: 1px;")
    return sep


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(3)
        layout.setContentsMargins(6, 4, 6, 4)

        # ── Row 0: Title row ────────────────────────────────────────
        title_row = QHBoxLayout()
        title_row.setSpacing(12)

        title = QLabel("[ NETWORK MONITOR DASHBOARD ]")
        title.setStyleSheet(
            f"color: {theme.GREEN}; font-size: 15px; font-weight: bold; padding: 2px;"
        )
        title_row.addWidget(title)

        self._baseline_indicator = QLabel("")
        self._baseline_indicator.setStyleSheet(
            f"color: {theme.AMBER}; font-size: 11px; padding: 2px;"
        )
        title_row.addWidget(self._baseline_indicator)
        title_row.addStretch()

        # Compact network info inline
        self._card_local_ip_label = QLabel("IP: \u2014")
        self._card_local_ip_label.setStyleSheet(
            f"color: {theme.GREEN_DIM}; font-size: 11px;"
        )
        self._card_subnet_label = QLabel("NET: \u2014")
        self._card_subnet_label.setStyleSheet(
            f"color: {theme.GREEN_DIM}; font-size: 11px;"
        )
        title_row.addWidget(self._card_local_ip_label)
        title_row.addWidget(self._card_subnet_label)

        layout.addLayout(title_row)
        layout.addWidget(_make_separator())

        # ── Row 1: Gauges + compact side panel ──────────────────────
        gauge_row = QHBoxLayout()
        gauge_row.setSpacing(4)

        self._gauge_score = RadialGauge(
            title="SECURITY", unit="pts", min_val=0, max_val=100
        )
        self._gauge_score.set_value(100)
        self._gauge_bw = RadialGauge(
            title="BANDWIDTH", unit="%", min_val=0, max_val=100
        )
        self._gauge_latency = RadialGauge(
            title="LATENCY", unit="ms", min_val=0, max_val=200
        )
        self._gauge_threat = RadialGauge(
            title="THREAT", unit="", min_val=0, max_val=100
        )

        gauge_row.addWidget(self._gauge_score, stretch=1)
        gauge_row.addWidget(self._gauge_bw, stretch=1)
        gauge_row.addWidget(self._gauge_latency, stretch=1)
        gauge_row.addWidget(self._gauge_threat, stretch=1)

        # Side panel: compact stat cards + connection ring chart
        side_panel = QVBoxLayout()
        side_panel.setSpacing(2)

        self._card_devices = StatCard("Devices", "0", sparkline=True)
        self._card_devices.setMaximumWidth(170)
        self._card_devices.setMaximumHeight(70)
        self._card_alerts = StatCard("Alerts", "0", sparkline=True)
        self._card_alerts.setMaximumWidth(170)
        self._card_alerts.setMaximumHeight(70)

        # Mini connection state ring chart
        self._conn_ring = RingChart(title="States")
        self._conn_ring.setMaximumWidth(170)
        self._conn_ring.setMaximumHeight(110)

        side_panel.addWidget(self._card_devices)
        side_panel.addWidget(self._card_alerts)
        side_panel.addWidget(self._conn_ring)
        side_panel.addStretch()

        gauge_row.addLayout(side_panel, stretch=0)
        layout.addLayout(gauge_row)

        # ── Row 2: Topology + World Map (main visual area) ────────
        map_splitter = QSplitter(Qt.Horizontal)
        map_splitter.setChildrenCollapsible(False)

        self._topology_map = TopologyMapWidget()
        self._topology_map.setMinimumHeight(180)
        self._world_map = WorldMapWidget()
        self._world_map.setMinimumHeight(180)

        map_splitter.addWidget(self._topology_map)
        map_splitter.addWidget(self._world_map)
        map_splitter.setStretchFactor(0, 2)
        map_splitter.setStretchFactor(1, 3)
        layout.addWidget(map_splitter, stretch=3)

        # ── Row 3: Charts + Timeline/Heatmap ──────────────────────
        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.setChildrenCollapsible(False)

        # Left: BW + Latency charts stacked
        charts_widget = QWidget()
        charts_layout = QVBoxLayout(charts_widget)
        charts_layout.setContentsMargins(0, 0, 0, 0)
        charts_layout.setSpacing(2)

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

        # Right: Security timeline + traffic heatmap
        sec_widget = QWidget()
        sec_layout = QVBoxLayout(sec_widget)
        sec_layout.setContentsMargins(0, 0, 0, 0)
        sec_layout.setSpacing(2)

        timeline_label = QLabel("SECURITY EVENTS (24H)")
        timeline_label.setStyleSheet(theme.SECTION_LABEL)
        sec_layout.addWidget(timeline_label)
        self._security_timeline = SecurityTimeline()
        sec_layout.addWidget(self._security_timeline)

        heatmap_label = QLabel("TRAFFIC HEATMAP")
        heatmap_label.setStyleSheet(theme.SECTION_LABEL)
        sec_layout.addWidget(heatmap_label)
        self._traffic_heatmap = TrafficHeatmap()
        sec_layout.addWidget(self._traffic_heatmap)

        bottom_splitter.addWidget(charts_widget)
        bottom_splitter.addWidget(sec_widget)
        bottom_splitter.setStretchFactor(0, 3)
        bottom_splitter.setStretchFactor(1, 2)
        layout.addWidget(bottom_splitter, stretch=2)

        self._use_mb = False

    # ── Public API ────────────────────────────────────────────────

    def update_network_info(self, local_ip: str, subnet: str):
        self._card_local_ip_label.setText(f"IP: {local_ip}")
        self._card_subnet_label.setText(f"NET: {subnet}")

    def update_bandwidth_summary(self, speed_down: float, speed_up: float):
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
        self._latency_chart.add_data_point([avg_ms])
        self._gauge_latency.set_value(min(avg_ms, 200))

    def update_device_count(self, online: int):
        self._card_devices.set_value(str(online))
        self._card_devices.add_spark_point(float(online))

    def update_alert_count(self, count: int):
        self._card_alerts.set_value(str(count))
        self._card_alerts.add_spark_point(float(count))

    def update_security_score(self, score: int):
        self._gauge_score.set_value(score)
        self._gauge_threat.set_value(100 - score)

    def update_security_timeline(self, hourly_data: list[dict]):
        self._security_timeline.set_data(hourly_data)

    def update_traffic_heatmap(self, heatmap_data: list[dict]):
        self._traffic_heatmap.set_data(heatmap_data)

    def update_baseline_mode(self, mode: str):
        if mode == "learning":
            self._baseline_indicator.setText("[BASELINE: LEARNING]")
            self._baseline_indicator.setStyleSheet(
                f"color: {theme.AMBER}; font-size: 11px; padding: 2px;"
            )
        elif mode == "monitoring":
            self._baseline_indicator.setText("[BASELINE: ACTIVE]")
            self._baseline_indicator.setStyleSheet(
                f"color: {theme.GREEN}; font-size: 11px; padding: 2px;"
            )
        else:
            self._baseline_indicator.setText("")

    def update_connection_states(self, state_counts: dict[str, int]):
        """Update the connection state ring chart."""
        self._conn_ring.set_data(state_counts)

    # ── SOC dashboard methods ─────────────────────────────────────

    def update_topology(self, devices: list, gateway_ip: str,
                        trusted_macs: set | None = None):
        self._topology_map.update_devices(devices, gateway_ip, trusted_macs)

    def update_world_map(self, connections: list[dict]):
        self._world_map.update_connections(connections)

    def update_gauge_bandwidth(self, utilization_pct: float):
        self._gauge_bw.set_value(min(utilization_pct, 100))

    def set_world_map_local_coords(self, lat: float, lon: float):
        self._world_map.set_local_coords(lat, lon)
