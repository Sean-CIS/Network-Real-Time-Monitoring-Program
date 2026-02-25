from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
)

from src.gui import theme
from src.gui.alerts_view import AlertsView
from src.gui.bandwidth_view import BandwidthView
from src.gui.connections_view import ConnectionsView
from src.gui.dashboard import DashboardView
from src.gui.devices_view import DevicesView
from src.gui.dns_view import DNSView
from src.gui.latency_view import LatencyView
from src.gui.packets_view import PacketsView
from src.gui.ports_view import PortsView
from src.gui.security_events_view import SecurityEventsView
from src.gui.theme import ScanlineOverlay
from src.utils.network import is_admin


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("[ NETWORK REAL-TIME MONITOR ]")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        self._apply_theme()

        # Central tab widget
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.North)
        self._tabs.setStyleSheet(theme.TAB_STYLESHEET)

        # Create views
        self.dashboard_view = DashboardView()
        self.bandwidth_view = BandwidthView()
        self.latency_view = LatencyView()
        self.devices_view = DevicesView()
        self.ports_view = PortsView()
        self.packets_view = PacketsView()
        self.security_events_view = SecurityEventsView()
        self.connections_view = ConnectionsView()
        self.dns_view = DNSView()
        self.alerts_view = AlertsView()

        # Add tabs
        self._tabs.addTab(self.dashboard_view, "Dashboard")
        self._tabs.addTab(self.bandwidth_view, "Bandwidth")
        self._tabs.addTab(self.latency_view, "Latency")
        self._tabs.addTab(self.devices_view, "Devices")
        self._tabs.addTab(self.ports_view, "Port Scanner")
        self._tabs.addTab(self.packets_view, "Packet Capture")
        self._tabs.addTab(self.security_events_view, "Security Events")
        self._tabs.addTab(self.connections_view, "Connections")
        self._tabs.addTab(self.dns_view, "DNS History")
        self._tabs.addTab(self.alerts_view, "Alerts")

        self.setCentralWidget(self._tabs)

        # Status bar
        self._setup_status_bar()

        # Apply glow effects to dashboard widgets
        self._apply_glow_effects()

        # CRT scanline overlay
        self._scanlines = ScanlineOverlay(self)
        self._scanlines.raise_()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._scanlines.setGeometry(self.rect())

    def _setup_status_bar(self):
        status_bar = QStatusBar()
        status_bar.setStyleSheet(theme.STATUS_BAR_STYLE)
        self.setStatusBar(status_bar)

        # Admin status
        if is_admin():
            admin_label = QLabel("[ROOT]")
            admin_label.setStyleSheet(f"color: {theme.GREEN}; padding: 0 8px;")
        else:
            admin_label = QLabel("[USER] some features require elevation")
            admin_label.setStyleSheet(f"color: {theme.AMBER}; padding: 0 8px;")
        status_bar.addWidget(admin_label)

        # Network info placeholder — updated at runtime by app.py
        self._net_info_label = QLabel("")
        self._net_info_label.setStyleSheet(f"color: {theme.GREEN_DIM}; padding: 0 8px;")
        status_bar.addPermanentWidget(self._net_info_label)

    def set_network_status(self, gateway: str, subnet: str):
        self._net_info_label.setText(
            f"NET: {subnet}  |  GW: {gateway}"
        )

    def _apply_theme(self):
        self.setStyleSheet(theme.GLOBAL_STYLESHEET)

    def _apply_glow_effects(self):
        """Apply phosphor glow effects to key dashboard widgets."""
        dv = self.dashboard_view
        # Glow on gauges
        for gauge in (dv._gauge_score, dv._gauge_bw,
                      dv._gauge_latency, dv._gauge_threat):
            effect = theme.apply_glow(gauge, theme.GREEN_GLOW, blur_radius=12)
            anim = theme.PulsingGlow(effect, min_blur=6, max_blur=14,
                                     duration_ms=2000, parent=gauge)
            anim.start()

        # Glow on topology map
        theme.apply_glow(dv._topology_map, theme.GREEN_GLOW, blur_radius=10)

        # Glow on world map
        theme.apply_glow(dv._world_map, theme.GREEN_GLOW, blur_radius=10)
