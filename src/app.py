import socket
import sys
from collections import defaultdict

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QApplication

from src.core.alerts import AlertEngine
from src.core.anomaly import AnomalyDetector
from src.core.bandwidth import BandwidthMonitor
from src.core.connections import ConnectionsMonitor
from src.core.discovery import DiscoveryWorker
from src.core.dns_monitor import DNSMonitor
from src.core.flow_tracker import FlowTracker
from src.core.geoip import GeoIPResolver
from src.core.ids import IntrusionDetectionSystem
from src.core.latency import LatencyMonitor
from src.core.packet_capture import PacketCaptureWorker
from src.core.port_scanner import PortScanWorker
from src.core.set_defense import SETDefense
from src.core.threat_intel import ThreatIntelligence
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

        self._init_geoip()
        self._init_bandwidth()
        self._init_latency()
        self._init_discovery()
        self._init_connections()
        self._init_port_scanner()
        self._init_packet_capture()
        self._init_security_modules()
        self._init_alerts()

    # ── GeoIP ─────────────────────────────────────────────────

    def _init_geoip(self):
        self._geoip = GeoIPResolver()
        self._geoip.load_cache()
        self._geoip.resolved.connect(self._on_geoip_resolved)

    @Slot(dict)
    def _on_geoip_resolved(self, results: dict):
        """Called when a batch of IPs has been geo-resolved."""
        self._update_world_map()
        # Push updated geo data to connections view
        self._window.connections_view.set_geoip_data(self._geoip.get_all_cached())

    def _update_world_map(self):
        """Aggregate GeoIP data into connection endpoints for the world map."""
        cache = self._geoip.get_all_cached()
        if not cache:
            return

        # Aggregate by (lat, lon) rounded to reduce duplicates
        agg = defaultdict(lambda: {"lat": 0, "lon": 0, "country": "", "city": "", "isp": "", "count": 0})
        for ip, info in cache.items():
            lat = round(info.get("lat", 0), 1)
            lon = round(info.get("lon", 0), 1)
            key = (lat, lon)
            agg[key]["lat"] = info.get("lat", 0)
            agg[key]["lon"] = info.get("lon", 0)
            agg[key]["country"] = info.get("country", "")
            agg[key]["city"] = info.get("city", "")
            agg[key]["isp"] = info.get("isp", "")
            agg[key]["count"] += 1

        self._window.dashboard_view.world_map.set_connections(list(agg.values()))

        # Update top destinations table
        country_agg = defaultdict(lambda: {"country": "", "city": "", "count": 0})
        for info in agg.values():
            country = info.get("country", "Unknown")
            country_agg[country]["country"] = country
            country_agg[country]["city"] = info.get("city", "")
            country_agg[country]["count"] += info.get("count", 0)
        self._window.dashboard_view.update_top_destinations(list(country_agg.values()))

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

        # Feed anomaly detector
        if hasattr(self, "_anomaly"):
            self._anomaly.update_bandwidth(data)

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
            # Tell IDS to suppress self-scan alerts
            if hasattr(self, "_ids"):
                self._ids.set_scan_active(True)
            # Mascot → scanning state
            self._window.dashboard_view.mascot.set_state("scanning")
            self._discovery_worker.start()

    @Slot(list)
    def _on_discovery_complete(self, devices: list):
        # Turn off scan suppression
        if hasattr(self, "_ids"):
            self._ids.set_scan_active(False)

        all_devices = db.get_all_devices()
        self._window.devices_view.update_devices(all_devices)
        self._alert_engine.check_devices(devices)
        online = sum(1 for d in all_devices if d.get("is_online"))
        self._window.dashboard_view.update_device_count(online)

        # Update topology map
        self._window.dashboard_view.topology_map.set_devices(all_devices)

        # Update mascot device count + go back to idle
        self._window.dashboard_view.mascot.set_device_count(online)
        self._window.dashboard_view.mascot.set_state("idle")

    # ── Connections Monitor ───────────────────────────────────

    def _init_connections(self):
        interval = get("connections", "poll_interval_s", 2)
        self._conn_monitor = ConnectionsMonitor(interval_s=interval)
        self._conn_monitor.data_ready.connect(self._on_connections_data)
        self._conn_monitor.error_occurred.connect(self._on_error)
        if get("connections", "enabled", True):
            self._conn_monitor.start()

    @Slot(list)
    def _on_connections_data(self, connections: list):
        # Push GeoIP data to connections view
        self._window.connections_view.set_geoip_data(self._geoip.get_all_cached())
        self._window.connections_view.update_connections(connections)

        # Update dashboard counts
        remote_ips = set()
        for c in connections:
            rip = c.get("remote_ip", "")
            if rip:
                remote_ips.add(rip)

        geo_cache = self._geoip.get_all_cached()
        destinations = len(set(
            geo_cache[ip].get("country", "") for ip in remote_ips if ip in geo_cache
        ))
        self._window.dashboard_view.update_connection_count(len(connections), destinations)

        # Queue new external IPs for GeoIP resolution
        self._geoip.queue_ips(remote_ips)
        self._geoip.resolve_now()

        # Feed anomaly detector
        if hasattr(self, "_anomaly"):
            self._anomaly.update_connections(connections)

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
            # Suppress IDS alerts during port scan
            if hasattr(self, "_ids"):
                self._ids.set_scan_active(True)
            # Mascot → scanning state
            self._window.dashboard_view.mascot.set_state("scanning")
            self._port_worker.start()

    @Slot(list)
    def _on_port_scan_complete(self, results: list):
        if hasattr(self, "_ids"):
            self._ids.set_scan_active(False)
        self._window.ports_view.update_results(results)
        # Mascot → back to idle
        self._window.dashboard_view.mascot.set_state("idle")

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

    # ── Security Modules ───────────────────────────────────────

    def _init_security_modules(self):
        """Initialize IDS, DNS Monitor, Flow Tracker, Threat Intel, Anomaly, SET Defense."""

        # Intrusion Detection System
        self._ids = IntrusionDetectionSystem()
        self._ids.security_event.connect(self._on_security_event)
        self._ids.security_event.connect(self._window.security_view.add_event)

        # DNS Monitor
        self._dns_monitor = DNSMonitor()
        self._dns_monitor.dns_stats_updated.connect(self._on_dns_stats)
        self._dns_monitor.dns_query_logged.connect(self._window.dns_view.add_query)

        # Flow Tracker
        self._flow_tracker = FlowTracker()
        self._flow_tracker.flow_stats_updated.connect(self._on_flow_stats)

        # Threat Intelligence
        self._threat_intel = ThreatIntelligence()
        self._threat_intel.threat_alert.connect(self._on_security_event)
        self._threat_intel.threat_alert.connect(self._window.security_view.add_event)
        self._threat_intel.threat_scored.connect(self._window.security_view.update_threat_score)

        # Anomaly Detector
        self._anomaly = AnomalyDetector()
        self._anomaly.anomaly_detected.connect(self._on_security_event)
        self._anomaly.anomaly_detected.connect(self._window.security_view.add_event)

        # SET Defense
        self._set_defense = SETDefense()
        self._set_defense.set_defense_alert.connect(self._on_set_defense_event)
        self._set_defense.set_defense_alert.connect(self._window.set_defense_view.add_event)
        self._set_defense.set_defense_alert.connect(self._window.security_view.add_event)

        # Wire packet capture to security modules
        self._capture_worker.raw_packet_data.connect(self._ids.process_packet)
        self._capture_worker.raw_packet_data.connect(self._flow_tracker.process_packet)
        self._capture_worker.raw_packet_data.connect(self._set_defense.process_packet)

        # Wire DNS packets
        self._capture_worker.dns_packet.connect(self._dns_monitor.process_dns)
        self._capture_worker.dns_packet.connect(self._threat_intel.check_domain)
        self._capture_worker.dns_packet.connect(self._set_defense.check_dns_query)

        # Wire DNS monitor anomalies to anomaly detector
        self._dns_monitor.dns_stats_updated.connect(
            lambda stats: self._anomaly.update_dns_rate(
                stats.get("query_rate", 0) * 60  # convert per-sec to per-min
            )
        )

        # Wire flow stats to SET defense for C2 beaconing detection
        self._flow_tracker.flow_stats_updated.connect(self._set_defense.check_flows)

        # Detect local IPs and tell IDS so it can suppress self-scan alerts
        self._ids.set_local_ips(self._detect_local_ips())

    @Slot(dict)
    def _on_security_event(self, event: dict):
        """Handle security events from IDS, threat intel, anomaly detector."""
        self._alert_engine.check_security_event(event)
        # Trigger mascot alert state on warning/critical
        severity = event.get("severity", "").lower()
        if severity in ("warning", "critical"):
            self._window.dashboard_view.mascot.set_state("alert")

    @Slot(dict)
    def _on_set_defense_event(self, event: dict):
        """Handle SET defense events."""
        self._alert_engine.check_security_event(event)

    @Slot(dict)
    def _on_dns_stats(self, stats: dict):
        """Handle DNS monitor stats updates."""
        self._window.dns_view.update_stats(stats)
        self._window.dashboard_view.update_dns_stats(stats)

    @Slot(dict)
    def _on_flow_stats(self, stats: dict):
        """Handle flow tracker stats updates."""
        self._window.dashboard_view.update_flow_stats(stats)

        # Feed anomaly detector with packet rate
        if hasattr(self, "_anomaly"):
            self._anomaly.update_packet_rate(stats.get("total_packets", 0))

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
        self._window.dashboard_view.update_alert_ticker(alerts)

    @Slot(dict)
    def _on_alert(self, alert: dict):
        alerts = db.get_recent_alerts(100)
        self._window.alerts_view.update_alerts(alerts)
        self._window.dashboard_view.update_alert_count(len(alerts))
        self._window.dashboard_view.update_alert_ticker(alerts)

    def _clear_alerts(self):
        self._window.alerts_view.clear_alerts()

    # ── Utility ─────────────────────────────────────────────────

    @staticmethod
    def _detect_local_ips() -> set[str]:
        """Detect all local IP addresses on this machine."""
        local_ips = {"127.0.0.1"}
        try:
            import psutil
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        local_ips.add(addr.address)
        except ImportError:
            try:
                hostname = socket.gethostname()
                for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                    local_ips.add(info[4][0])
            except OSError:
                pass
        return local_ips

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
        if hasattr(self, "_conn_monitor"):
            self._conn_monitor.stop()
        if hasattr(self, "_geoip"):
            self._geoip.stop()
        if hasattr(self, "_capture_worker") and self._capture_worker.isRunning():
            self._capture_worker.stop()
