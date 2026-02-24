import sys

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QApplication

from src.core.alerts import AlertEngine
from src.core.bandwidth import BandwidthMonitor
from src.core.discovery import DiscoveryWorker
from src.core.latency import LatencyMonitor
from src.core.packet_capture import PacketCaptureWorker
from src.core.port_scanner import PortScanWorker
from src.gui.main_window import MainWindow
from src.utils import db
from src.utils.config import get, load_config


class NetworkMonitorApp:
    """Main application controller — wires core workers to GUI views."""

    def __init__(self):
        self._qapp = QApplication(sys.argv)
        self._qapp.setApplicationName("Network Real-Time Monitor")

        load_config()
        db.init_db()

        self._window = MainWindow()
        self._alert_engine = AlertEngine()

        self._init_bandwidth()
        self._init_latency()
        self._init_discovery()
        self._init_port_scanner()
        self._init_packet_capture()
        self._init_alerts()

    # ── Bandwidth ──────────────────────────────────────────────

    def _init_bandwidth(self):
        interval = get("bandwidth", "poll_interval_s", 1)
        self._bw_monitor = BandwidthMonitor(interval_s=interval)
        self._bw_monitor.data_ready.connect(self._on_bandwidth_data)
        self._bw_monitor.error_occurred.connect(self._on_error)
        if get("bandwidth", "enabled", True):
            self._bw_monitor.start()

    @Slot(dict)
    def _on_bandwidth_data(self, data: dict):
        self._window.bandwidth_view.update_bandwidth(data)
        self._alert_engine.check_bandwidth(data)

        # Update dashboard with total across all interfaces
        total_down = sum(v.get("speed_down", 0) for v in data.values())
        total_up = sum(v.get("speed_up", 0) for v in data.values())
        self._window.dashboard_view.update_bandwidth_summary(total_down, total_up)

    # ── Latency ────────────────────────────────────────────────

    def _init_latency(self):
        interval = get("latency", "poll_interval_s", 2)
        targets = get("latency", "targets", [])
        self._latency_monitor = LatencyMonitor(targets=targets, interval_s=interval)
        self._latency_monitor.data_ready.connect(self._on_latency_data)
        self._latency_monitor.error_occurred.connect(self._on_error)

        if targets:
            labels = [t.get("label", t.get("host", "")) for t in targets]
            self._window.latency_view.set_targets(labels)

        if get("latency", "enabled", True):
            self._latency_monitor.start()

    @Slot(list)
    def _on_latency_data(self, results: list):
        self._window.latency_view.update_latency(results)
        self._alert_engine.check_latency(results)

        # Update dashboard
        alive = [r for r in results if r.get("is_alive") and r.get("latency_ms")]
        if alive:
            avg = sum(r["latency_ms"] for r in alive) / len(alive)
            self._window.dashboard_view.update_latency_summary(avg)

    # ── Discovery ──────────────────────────────────────────────

    def _init_discovery(self):
        network = get("discovery", "network", "192.168.1.0/24")
        self._discovery_worker = DiscoveryWorker(network=network)
        self._discovery_worker.scan_complete.connect(self._on_discovery_complete)
        self._discovery_worker.scan_status.connect(
            self._window.devices_view.set_scan_status
        )
        self._window.devices_view.scan_button.clicked.connect(self._start_discovery)

    def _start_discovery(self):
        if not self._discovery_worker.isRunning():
            network = get("discovery", "network", "192.168.1.0/24")
            self._discovery_worker.set_network(network)
            self._discovery_worker.start()

    @Slot(list)
    def _on_discovery_complete(self, devices: list):
        all_devices = db.get_all_devices()
        self._window.devices_view.update_devices(all_devices)
        self._alert_engine.check_devices(devices)
        online = sum(1 for d in all_devices if d.get("is_online"))
        self._window.dashboard_view.update_device_count(online)

    # ── Port Scanner ───────────────────────────────────────────

    def _init_port_scanner(self):
        self._port_worker = PortScanWorker()
        self._port_worker.scan_complete.connect(self._on_port_scan_complete)
        self._port_worker.scan_status.connect(self._window.ports_view.set_status)
        self._window.ports_view.scan_button.clicked.connect(self._start_port_scan)

        # Connect device table selection to port scanner target
        self._window.devices_view.device_table.device_selected.connect(
            self._window.ports_view.set_target
        )

    def _start_port_scan(self):
        if not self._port_worker.isRunning():
            target = self._window.ports_view.target_ip
            ports = self._window.ports_view.port_range or get(
                "port_scanner", "default_ports", "1-1024"
            )
            self._port_worker.set_target(target, ports)
            self._port_worker.start()

    @Slot(list)
    def _on_port_scan_complete(self, results: list):
        self._window.ports_view.update_results(results)

    # ── Packet Capture ─────────────────────────────────────────

    def _init_packet_capture(self):
        self._capture_worker = PacketCaptureWorker()
        self._capture_worker.packet_captured.connect(self._window.packets_view.add_packet)
        self._capture_worker.proto_stats.connect(self._window.packets_view.update_proto_chart)
        self._capture_worker.capture_status.connect(
            lambda s: self._window.packets_view.set_capturing(s == "Capturing...")
        )
        self._window.packets_view.start_button.clicked.connect(self._start_capture)
        self._window.packets_view.stop_button.clicked.connect(self._stop_capture)

    def _start_capture(self):
        if not self._capture_worker.isRunning():
            self._window.packets_view.clear_packets()
            bpf = self._window.packets_view.filter_text or get(
                "packet_capture", "default_filter", ""
            )
            self._capture_worker.set_filter(bpf)
            self._capture_worker.start()
            self._window.packets_view.set_capturing(True)

    def _stop_capture(self):
        self._capture_worker.stop()
        self._window.packets_view.set_capturing(False)

    # ── Alerts ─────────────────────────────────────────────────

    def _init_alerts(self):
        bw_thresh = get("alerts", "bandwidth_threshold_mbps", 100)
        lat_thresh = get("alerts", "latency_threshold_ms", 200)
        offline_timeout = get("alerts", "device_offline_timeout_s", 60)
        cooldown = get("alerts", "cooldown_s", 300)
        self._alert_engine.configure(bw_thresh, lat_thresh, offline_timeout, cooldown)

        self._alert_engine.alert_triggered.connect(self._on_alert)
        self._window.alerts_view.clear_button.clicked.connect(self._clear_alerts)

        # Load existing alerts
        alerts = db.get_recent_alerts(100)
        self._window.alerts_view.update_alerts(alerts)
        self._window.dashboard_view.update_alert_count(len(alerts))

    @Slot(dict)
    def _on_alert(self, alert: dict):
        alerts = db.get_recent_alerts(100)
        self._window.alerts_view.update_alerts(alerts)
        self._window.dashboard_view.update_alert_count(len(alerts))

    def _clear_alerts(self):
        self._window.alerts_view.clear_alerts()

    # ── Error handling ─────────────────────────────────────────

    @Slot(str)
    def _on_error(self, error: str):
        print(f"[Monitor Error] {error}")

    # ── Run ────────────────────────────────────────────────────

    def run(self) -> int:
        self._window.show()
        code = self._qapp.exec()
        self._shutdown()
        return code

    def _shutdown(self):
        if hasattr(self, "_bw_monitor"):
            self._bw_monitor.stop()
        if hasattr(self, "_latency_monitor"):
            self._latency_monitor.stop()
        if hasattr(self, "_capture_worker") and self._capture_worker.isRunning():
            self._capture_worker.stop()
