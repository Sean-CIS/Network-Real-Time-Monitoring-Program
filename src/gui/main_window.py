from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QWidget,
)

from src.gui.alerts_view import AlertsView
from src.gui.bandwidth_view import BandwidthView
from src.gui.dashboard import DashboardView
from src.gui.devices_view import DevicesView
from src.gui.latency_view import LatencyView
from src.gui.packets_view import PacketsView
from src.gui.ports_view import PortsView
from src.utils.network import is_admin


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Real-Time Monitor")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        self._apply_theme()

        # Central tab widget
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.North)
        self._tabs.setStyleSheet(
            """
            QTabWidget::pane {
                border: 1px solid #45475a;
                background-color: #1e1e2e;
            }
            QTabBar::tab {
                background-color: #313244;
                color: #cdd6f4;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #45475a;
                color: #89b4fa;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #585b70;
            }
            """
        )

        # Create views
        self.dashboard_view = DashboardView()
        self.bandwidth_view = BandwidthView()
        self.latency_view = LatencyView()
        self.devices_view = DevicesView()
        self.ports_view = PortsView()
        self.packets_view = PacketsView()
        self.alerts_view = AlertsView()

        # Add tabs
        self._tabs.addTab(self.dashboard_view, "Dashboard")
        self._tabs.addTab(self.bandwidth_view, "Bandwidth")
        self._tabs.addTab(self.latency_view, "Latency")
        self._tabs.addTab(self.devices_view, "Devices")
        self._tabs.addTab(self.ports_view, "Port Scanner")
        self._tabs.addTab(self.packets_view, "Packet Capture")
        self._tabs.addTab(self.alerts_view, "Alerts")

        self.setCentralWidget(self._tabs)

        # Status bar
        self._setup_status_bar()

    def _setup_status_bar(self):
        status_bar = QStatusBar()
        status_bar.setStyleSheet(
            "QStatusBar { background-color: #313244; color: #cdd6f4; "
            "border-top: 1px solid #45475a; padding: 2px; }"
            "QStatusBar::item { border: none; }"
        )
        self.setStatusBar(status_bar)

        # Admin status
        if is_admin():
            admin_label = QLabel("Running as root")
            admin_label.setStyleSheet("color: #a6e3a1; padding: 0 8px;")
        else:
            admin_label = QLabel("Running as user (some features require elevation)")
            admin_label.setStyleSheet("color: #f9e2af; padding: 0 8px;")
        status_bar.addWidget(admin_label)

        # Network info placeholder — updated at runtime by app.py
        self._net_info_label = QLabel("")
        self._net_info_label.setStyleSheet("color: #a6adc8; padding: 0 8px;")
        status_bar.addPermanentWidget(self._net_info_label)

    def set_network_status(self, gateway: str, subnet: str):
        """Update the status bar with detected network info."""
        self._net_info_label.setText(
            f"Network: {subnet}  |  Gateway: {gateway}"
        )

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #1e1e2e;
            }
            QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: "Segoe UI", "Consolas", monospace;
                font-size: 13px;
            }
            QLabel {
                color: #cdd6f4;
            }
            QLineEdit {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 6px;
            }
            QComboBox {
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 6px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #313244;
                color: #cdd6f4;
                selection-background-color: #45475a;
            }
            QScrollBar:vertical {
                background: #1e1e2e;
                width: 10px;
            }
            QScrollBar::handle:vertical {
                background: #45475a;
                border-radius: 5px;
            }
            """
        )
