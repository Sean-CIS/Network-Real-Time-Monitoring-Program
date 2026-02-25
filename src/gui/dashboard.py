"""Enhanced NOC-style dashboard with world map, topology, gauges, and charts."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.gauge import CircularGauge
from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard
from src.gui.widgets.topology_map import TopologyMapWidget
from src.gui.widgets.world_map import WorldMapWidget


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 8, 8, 8)

        # ── Row 1: Stat cards ─────────────────────────────────
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        self._card_download = StatCard("Download", "---")
        self._card_upload = StatCard("Upload", "---")
        self._card_latency = StatCard("Avg Latency", "---")
        self._card_devices = StatCard("Devices Online", "0")
        self._card_connections = StatCard("Connections", "0")
        self._card_destinations = StatCard("Destinations", "0")
        self._card_alerts = StatCard("Active Alerts", "0")

        for card in (self._card_download, self._card_upload, self._card_latency,
                     self._card_devices, self._card_connections,
                     self._card_destinations, self._card_alerts):
            top_row.addWidget(card)

        layout.addLayout(top_row)

        # ── Row 2: World Map + Network Topology (side by side) ─
        maps_splitter = QSplitter(Qt.Horizontal)
        maps_splitter.setStyleSheet(
            "QSplitter::handle { background-color: #45475a; width: 2px; }"
        )

        # World map (left, 60%)
        map_frame = QFrame()
        map_frame.setFrameShape(QFrame.StyledPanel)
        map_frame.setStyleSheet(
            "QFrame { background-color: #11111b; border: 1px solid #45475a; border-radius: 6px; }"
        )
        map_layout = QVBoxLayout(map_frame)
        map_layout.setContentsMargins(2, 2, 2, 2)
        self._world_map = WorldMapWidget()
        map_layout.addWidget(self._world_map)

        # Topology (right, 40%)
        topo_frame = QFrame()
        topo_frame.setFrameShape(QFrame.StyledPanel)
        topo_frame.setStyleSheet(
            "QFrame { background-color: #11111b; border: 1px solid #45475a; border-radius: 6px; }"
        )
        topo_layout = QVBoxLayout(topo_frame)
        topo_layout.setContentsMargins(2, 2, 2, 2)
        self._topology_map = TopologyMapWidget()
        topo_layout.addWidget(self._topology_map)

        maps_splitter.addWidget(map_frame)
        maps_splitter.addWidget(topo_frame)
        maps_splitter.setSizes([600, 400])
        layout.addWidget(maps_splitter, stretch=3)

        # ── Row 3: Gauges + Charts + Top Destinations ─────────
        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.setStyleSheet(
            "QSplitter::handle { background-color: #45475a; width: 2px; }"
        )

        # Gauges panel
        gauges_frame = QFrame()
        gauges_frame.setFrameShape(QFrame.StyledPanel)
        gauges_frame.setStyleSheet(
            "QFrame { background-color: #1e1e2e; border: 1px solid #45475a; border-radius: 6px; }"
        )
        gauges_layout = QHBoxLayout(gauges_frame)
        gauges_layout.setContentsMargins(4, 4, 4, 4)
        self._gauge_download = CircularGauge("Download", "MB/s", max_value=100)
        self._gauge_upload = CircularGauge("Upload", "MB/s", max_value=100)
        self._gauge_latency = CircularGauge("Latency", "ms", max_value=500)
        gauges_layout.addWidget(self._gauge_download)
        gauges_layout.addWidget(self._gauge_upload)
        gauges_layout.addWidget(self._gauge_latency)

        # Charts panel
        charts_frame = QFrame()
        charts_frame.setFrameShape(QFrame.StyledPanel)
        charts_frame.setStyleSheet(
            "QFrame { background-color: #1e1e2e; border: 1px solid #45475a; border-radius: 6px; }"
        )
        charts_layout = QVBoxLayout(charts_frame)
        charts_layout.setContentsMargins(4, 4, 4, 4)
        self._bandwidth_chart = LiveChart(
            title="Bandwidth", y_label="KB/s",
            num_lines=2, line_labels=["Down", "Up"], max_points=120,
        )
        self._latency_chart = LiveChart(
            title="Latency", y_label="ms",
            num_lines=1, line_labels=["Avg"], max_points=120,
        )
        charts_layout.addWidget(self._bandwidth_chart)
        charts_layout.addWidget(self._latency_chart)

        # Top destinations table
        dest_frame = QFrame()
        dest_frame.setFrameShape(QFrame.StyledPanel)
        dest_frame.setStyleSheet(
            "QFrame { background-color: #1e1e2e; border: 1px solid #45475a; border-radius: 6px; }"
        )
        dest_layout = QVBoxLayout(dest_frame)
        dest_layout.setContentsMargins(4, 4, 4, 4)
        dest_title = QLabel("Top Destinations")
        dest_title.setStyleSheet("color: #cdd6f4; font-size: 12px; font-weight: bold; padding: 2px;")
        dest_layout.addWidget(dest_title)

        self._dest_table = QTableWidget()
        self._dest_table.setColumnCount(3)
        self._dest_table.setHorizontalHeaderLabels(["Country", "Connections", "City"])
        self._dest_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._dest_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._dest_table.setStyleSheet(
            """
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4;
                gridline-color: #313244; border: none; font-size: 11px;
            }
            QHeaderView::section {
                background-color: #313244; color: #a6adc8;
                padding: 4px; border: 1px solid #45475a; font-size: 10px;
            }
            QTableWidget::item:alternate { background-color: #181825; }
            """
        )
        self._dest_table.setAlternatingRowColors(True)
        self._dest_table.setMaximumHeight(200)
        dest_layout.addWidget(self._dest_table)

        bottom_splitter.addWidget(gauges_frame)
        bottom_splitter.addWidget(charts_frame)
        bottom_splitter.addWidget(dest_frame)
        bottom_splitter.setSizes([300, 400, 300])
        layout.addWidget(bottom_splitter, stretch=2)

        # ── Row 4: Alert ticker ───────────────────────────────
        self._alert_ticker = QLabel("No recent alerts")
        self._alert_ticker.setStyleSheet(
            "QLabel { background-color: #313244; color: #f9e2af; "
            "padding: 6px 12px; border-radius: 4px; font-size: 11px; }"
        )
        self._alert_ticker.setFixedHeight(28)
        layout.addWidget(self._alert_ticker)

    # ── Public API ────────────────────────────────────────────

    @property
    def world_map(self) -> WorldMapWidget:
        return self._world_map

    @property
    def topology_map(self) -> TopologyMapWidget:
        return self._topology_map

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
        self._gauge_download.set_value(speed_down / 1_000_000)
        self._gauge_upload.set_value(speed_up / 1_000_000)

    def update_latency_summary(self, avg_ms: float):
        self._card_latency.set_value(f"{avg_ms:.1f} ms")
        self._latency_chart.add_data_point([avg_ms])
        self._gauge_latency.set_value(avg_ms)

    def update_device_count(self, online: int):
        self._card_devices.set_value(str(online))

    def update_alert_count(self, count: int):
        self._card_alerts.set_value(str(count))

    def update_connection_count(self, total: int, destinations: int):
        self._card_connections.set_value(str(total))
        self._card_destinations.set_value(str(destinations))

    def update_top_destinations(self, destinations: list[dict]):
        sorted_dests = sorted(destinations, key=lambda d: d.get("count", 0), reverse=True)[:10]
        self._dest_table.setRowCount(len(sorted_dests))
        for row, d in enumerate(sorted_dests):
            self._dest_table.setItem(row, 0, QTableWidgetItem(d.get("country", "")))
            self._dest_table.setItem(row, 1, QTableWidgetItem(str(d.get("count", 0))))
            self._dest_table.setItem(row, 2, QTableWidgetItem(d.get("city", "")))

    def update_alert_ticker(self, alerts: list[dict]):
        if not alerts:
            self._alert_ticker.setText("No recent alerts")
            return
        texts = []
        for a in alerts[:5]:
            sev = a.get("severity", "info").upper()
            msg = a.get("message", "")
            texts.append(f"[{sev}] {msg}")
        self._alert_ticker.setText("  |  ".join(texts))
