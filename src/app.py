import csv
import json
import sys

from PySide6.QtCore import QTimer, Slot
from PySide6.QtWidgets import QApplication, QFileDialog

from src.core.alerts import AlertEngine
from src.core.arp_monitor import ARPMonitor
from src.core.bandwidth import BandwidthMonitor
from src.core.baseline import NetworkBaseline
from src.core.connection_tracker import ConnectionTracker
from src.core.discovery import DiscoveryWorker
from src.core.latency import LatencyMonitor
from src.core.packet_capture import PacketCaptureWorker
from src.core.port_scanner import PortScanWorker
from src.core.report_generator import generate_capture_report
from src.gui.main_window import MainWindow
from src.utils import db
from src.utils.config import get, load_config
from src.utils.network import detect_network_info
from src.utils.vuln_hints import SECURITY_SCAN_PORTS


class NetworkMonitorApp:
    """Main application controller — wires core workers to GUI views."""

    def __init__(self):
        self._qapp = QApplication(sys.argv)
        self._qapp.setApplicationName("Network Real-Time Monitor")

        load_config()
        db.init_db()

        # Auto-detect network info (gateway, local IP, subnet)
        self._network_info = detect_network_info()

        self._window = MainWindow()
        self._alert_engine = AlertEngine()

        # Push detected network info to UI
        self._window.dashboard_view.update_network_info(
            self._network_info["local_ip"],
            self._network_info["subnet_cidr"],
        )
        self._window.set_network_status(
            self._network_info["gateway_ip"],
            self._network_info["subnet_cidr"],
        )

        self._init_bandwidth()
        self._init_latency()
        self._init_discovery()
        self._init_port_scanner()
        self._init_packet_capture()
        self._init_alerts()
        self._init_connection_tracker()
        self._init_security_events()
        self._init_security_score_timer()
        self._init_baseline()
        self._init_arp_monitor()
        self._init_dns_view()

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

        # Feed baseline
        if hasattr(self, "_baseline"):
            self._baseline.feed_bandwidth(total_down + total_up)

    # ── Latency ────────────────────────────────────────────────

    def _init_latency(self):
        interval = get("latency", "poll_interval_s", 2)
        targets = get("latency", "targets", [])

        # Replace the Default Gateway target host with the auto-detected gateway
        detected_gw = self._network_info["gateway_ip"]
        for t in targets:
            if t.get("label", "").lower() == "default gateway":
                t["host"] = detected_gw

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
        # Use auto-detected subnet instead of config default
        network = self._network_info["subnet_cidr"] or get(
            "discovery", "network", "192.168.1.0/24"
        )
        local_ip = self._network_info["local_ip"]
        self._discovery_network = network
        self._discovery_worker = DiscoveryWorker(
            network=network, local_ip=local_ip
        )
        self._discovery_worker.scan_complete.connect(self._on_discovery_complete)
        self._discovery_worker.scan_status.connect(
            self._window.devices_view.set_scan_status
        )
        self._window.devices_view.scan_button.clicked.connect(self._start_discovery)

        # Connect trust device signal from device table
        self._window.devices_view.device_table.trust_device.connect(self._trust_device)

    def _start_discovery(self):
        if not self._discovery_worker.isRunning():
            self._discovery_worker.set_network(self._discovery_network)
            self._discovery_worker.set_local_ip(self._network_info["local_ip"])
            self._discovery_worker.start()

    @Slot(list)
    def _on_discovery_complete(self, devices: list):
        # Force WAL checkpoint so main thread sees worker's writes
        conn = db.get_connection()
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")

        all_devices = db.get_all_devices()

        # Check for rogue devices and create security events
        self._alert_engine.check_rogue_devices(all_devices)

        # Get trusted MACs for UI highlighting
        trusted_macs = db.get_trusted_macs()
        self._window.devices_view.update_devices(all_devices, trusted_macs)

        self._alert_engine.check_devices(devices)
        online = sum(1 for d in all_devices if d.get("is_online"))
        self._window.dashboard_view.update_device_count(online)

    @Slot(str)
    def _trust_device(self, mac: str):
        """Mark a device as trusted in the baseline database."""
        db.mark_device_trusted(mac, trusted=True)
        # Refresh device list to update highlighting
        all_devices = db.get_all_devices()
        trusted_macs = db.get_trusted_macs()
        self._window.devices_view.update_devices(all_devices, trusted_macs)

    # ── Port Scanner ───────────────────────────────────────────

    def _init_port_scanner(self):
        self._port_worker = PortScanWorker()
        self._port_worker.scan_complete.connect(self._on_port_scan_complete)
        self._port_worker.scan_status.connect(self._window.ports_view.set_status)
        self._window.ports_view.scan_button.clicked.connect(self._start_port_scan)

        # Pre-populate target IP with auto-detected gateway
        detected_gw = self._network_info["gateway_ip"]
        if detected_gw:
            self._window.ports_view.set_target(detected_gw)

        # Connect device table selection to port scanner target
        self._window.devices_view.device_table.device_selected.connect(
            self._window.ports_view.set_target
        )

        # Connect Quick Security Scan button
        self._window.ports_view.quick_scan_clicked.connect(
            self._start_quick_security_scan
        )

    def _start_port_scan(self):
        if not self._port_worker.isRunning():
            target = self._window.ports_view.target_ip
            ports = self._window.ports_view.port_range or get(
                "port_scanner", "default_ports", "1-1024"
            )
            self._window.ports_view.scan_button.setEnabled(False)
            self._window.ports_view.quick_scan_button.setEnabled(False)
            self._capture_worker._threat_detector.set_scan_active(
                True, self._network_info["local_ip"], target
            )
            self._port_worker.set_target(target, ports)
            self._port_worker.start()

    def _start_quick_security_scan(self):
        """Run a security-focused scan on common exploit ports."""
        if self._port_worker.isRunning():
            return
        gateway = self._network_info["gateway_ip"]
        target = gateway or "127.0.0.1"
        ports = ",".join(str(p) for p in SECURITY_SCAN_PORTS)
        self._window.ports_view.set_target(target)
        self._window.ports_view.set_status("Running quick security scan...")
        self._window.ports_view.scan_button.setEnabled(False)
        self._window.ports_view.quick_scan_button.setEnabled(False)
        self._capture_worker._threat_detector.set_scan_active(
            True, self._network_info["local_ip"], target
        )
        self._port_worker.set_target(target, ports)
        self._port_worker.start()

    @Slot(list)
    def _on_port_scan_complete(self, results: list):
        self._window.ports_view.update_results(results)
        self._window.ports_view.scan_button.setEnabled(True)
        self._window.ports_view.quick_scan_button.setEnabled(True)
        self._capture_worker._threat_detector.set_scan_active(False)

    # ── Packet Capture ─────────────────────────────────────────

    def _init_packet_capture(self):
        self._capture_worker = PacketCaptureWorker()
        self._capture_worker.packet_captured.connect(self._window.packets_view.add_packet)
        self._capture_worker.proto_stats.connect(self._window.packets_view.update_proto_chart)
        self._capture_worker.protocol_dist.connect(
            self._window.packets_view.update_protocol_distribution
        )
        self._capture_worker.capture_status.connect(
            lambda s: self._window.packets_view.set_capturing(s == "Capturing...")
        )

        # Security events from packet analysis
        self._capture_worker.security_event.connect(self._on_security_event)

        # Warn if GeoIP database is missing
        if not self._capture_worker._geoip.has_database:
            self._window.statusBar().showMessage(
                "GeoIP database not found \u2014 country lookups disabled. "
                "Download GeoLite2-City.mmdb to data/",
                15000,
            )

        self._window.packets_view.start_button.clicked.connect(self._start_capture)
        self._window.packets_view.stop_button.clicked.connect(self._stop_capture)

        # Export / report / load buttons
        self._window.packets_view.export_pcap_clicked.connect(self._export_pcap)
        self._window.packets_view.export_csv_clicked.connect(self._export_csv)
        self._window.packets_view.generate_report_clicked.connect(self._generate_report)
        self._window.packets_view.load_pcap_clicked.connect(self._load_pcap)

        # Top talkers timer (updates every 5 seconds during capture)
        self._top_talkers_timer = QTimer()
        self._top_talkers_timer.setInterval(5000)
        self._top_talkers_timer.timeout.connect(self._update_top_talkers)

    def _start_capture(self):
        if not self._capture_worker.isRunning():
            self._window.packets_view.clear_packets()
            bpf = self._window.packets_view.filter_text or get(
                "packet_capture", "default_filter", ""
            )
            self._capture_worker.set_filter(bpf)
            self._capture_worker.start()
            self._window.packets_view.set_capturing(True)
            self._top_talkers_timer.start()

    def _stop_capture(self):
        self._capture_worker.stop()
        self._window.packets_view.set_capturing(False)
        self._top_talkers_timer.stop()
        # Final top talkers update
        self._update_top_talkers()

    def _update_top_talkers(self):
        if hasattr(self._capture_worker, "get_top_talkers"):
            talkers = self._capture_worker.get_top_talkers()
            geoip = self._capture_worker.get_geoip()
            for t in talkers:
                ip = t.get("ip", "")
                if geoip.is_private(ip):
                    t["country"] = "Local"
                else:
                    geo = geoip.lookup(ip)
                    cc = geo.get("country_code", "")
                    t["country"] = cc if cc and cc != "?" else "N/A"
            self._window.packets_view.update_top_talkers(talkers)

    # ── PCAP Replay ───────────────────────────────────────────

    def _load_pcap(self):
        """Load a PCAP file and replay packets through the analysis engine."""
        path, _ = QFileDialog.getOpenFileName(
            self._window, "Open PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if not path:
            return
        try:
            from scapy.all import rdpcap
            packets = rdpcap(path)
            self._window.packets_view.clear_packets()

            for pkt in packets:
                info = self._capture_worker.analyze_single_packet(pkt)
                # Run threat detection
                events = self._capture_worker._threat_detector.analyze_packet(info, pkt)
                if events:
                    severities = [e["severity"] for e in events]
                    if "critical" in severities:
                        info["threat_level"] = "critical"
                    elif "warning" in severities:
                        info["threat_level"] = "warning"
                    else:
                        info["threat_level"] = "info"
                    for event in events:
                        self._on_security_event(event)

                self._window.packets_view.add_packet(info)

            # Update protocol distribution
            self._window.packets_view.update_protocol_distribution(
                self._capture_worker.get_protocol_counts()
            )

        except Exception as e:
            print(f"[Load PCAP Error] {e}")

    # ── Export / Report ────────────────────────────────────────

    def _export_pcap(self):
        path, _ = QFileDialog.getSaveFileName(
            self._window, "Save PCAP", "capture.pcap", "PCAP Files (*.pcap)"
        )
        if not path:
            return
        try:
            from scapy.all import wrpcap
            raw = self._capture_worker.get_raw_packets()
            if raw:
                wrpcap(path, raw)
        except Exception as e:
            print(f"[Export PCAP Error] {e}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self._window, "Save CSV", "packets.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            packets = self._capture_worker.get_captured_packets()
            if not packets:
                return
            fieldnames = [
                "time", "src", "dst", "protocol", "length", "info",
                "threat_level", "country_src", "country_dst", "process",
            ]
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(
                    f, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writeheader()
                writer.writerows(packets)
        except Exception as e:
            print(f"[Export CSV Error] {e}")

    def _generate_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self._window, "Save Report", "capture_report.html", "HTML Files (*.html)"
        )
        if not path:
            return
        try:
            metadata = self._capture_worker.get_capture_metadata()
            packets = self._capture_worker.get_captured_packets()
            events = self._capture_worker.get_security_events()
            top_talkers = self._capture_worker.get_top_talkers()

            # GeoIP batch lookup for external IPs
            geoip = self._capture_worker.get_geoip()
            external_ips = set()
            for p in packets:
                for key in ("src", "dst"):
                    ip = p.get(key, "")
                    if ip and not geoip.is_private(ip):
                        external_ips.add(ip)
            geoip_data = geoip.lookup_batch(list(external_ips))

            html = generate_capture_report(
                metadata, packets, events, geoip_data, top_talkers
            )
            with open(path, "w") as f:
                f.write(html)
        except Exception as e:
            print(f"[Report Error] {e}")

    # ── Security Events ────────────────────────────────────────

    def _init_security_events(self):
        """Load existing security events from DB and wire clear button."""
        events = db.get_recent_security_events(200)
        self._window.security_events_view.update_events(events)
        self._window.security_events_view.clear_button.clicked.connect(
            self._clear_security_events
        )

    @Slot(dict)
    def _on_security_event(self, event: dict):
        """Handle a security event from the packet capture threat detector."""
        db.insert_security_event(
            severity=event.get("severity", "info"),
            event_type=event.get("event_type", "unknown"),
            description=event.get("description", ""),
            source_ip=event.get("source_ip", ""),
            dest_ip=event.get("dest_ip", ""),
            raw_details=json.dumps(event.get("raw_details", {}))
            if isinstance(event.get("raw_details"), dict) else
            str(event.get("raw_details", "")),
        )
        self._window.security_events_view.add_event(event)

    def _clear_security_events(self):
        db.clear_security_events()
        self._window.security_events_view.clear_events()

    # ── Connection Tracker ─────────────────────────────────────

    def _init_connection_tracker(self):
        interval = get("security", "connection_poll_interval_s", 3)
        self._conn_tracker = ConnectionTracker(interval_s=interval)
        self._conn_tracker.data_ready.connect(
            self._window.connections_view.update_connections
        )
        self._conn_tracker.data_ready.connect(self._on_connections_data)
        self._conn_tracker.new_destination.connect(self._on_new_destination)
        self._conn_tracker.error_occurred.connect(self._on_error)
        self._conn_tracker.start()

    @Slot(list)
    def _on_connections_data(self, conns: list):
        """Feed connection count to baseline."""
        if hasattr(self, "_baseline"):
            self._baseline.feed_connection_count(len(conns))

    @Slot(dict)
    def _on_new_destination(self, dest: dict):
        """Log first-time outbound destinations as info events."""
        db.insert_security_event(
            severity="info",
            event_type="new_destination",
            source_ip="",
            dest_ip=dest.get("remote_ip", ""),
            description=(
                f"New outbound destination: {dest.get('remote_ip', '?')}"
                f":{dest.get('remote_port', '?')} "
                f"(process: {dest.get('process', 'Unknown')})"
            ),
        )

    # ── Network Baseline ──────────────────────────────────────

    def _init_baseline(self):
        self._baseline = NetworkBaseline(interval_s=10.0)
        self._baseline.deviation_detected.connect(self._on_security_event)
        self._baseline.mode_changed.connect(
            self._window.dashboard_view.update_baseline_mode
        )
        self._baseline.start()

        # Set initial mode indicator
        mode = "learning" if self._baseline.is_learning else "monitoring"
        self._window.dashboard_view.update_baseline_mode(mode)

    # ── ARP Monitor ───────────────────────────────────────────

    def _init_arp_monitor(self):
        self._arp_monitor = ARPMonitor(interval_s=10.0)
        self._arp_monitor.arp_table_updated.connect(
            self._window.devices_view.update_arp_table
        )
        self._arp_monitor.arp_change.connect(self._on_arp_change)
        self._arp_monitor.start()

    @Slot(dict)
    def _on_arp_change(self, change: dict):
        """Handle ARP MAC change — create security event and update UI."""
        self._window.devices_view.on_arp_change(change)
        event = {
            "timestamp": change.get("timestamp", ""),
            "severity": "warning",
            "event_type": "arp_mac_change",
            "source_ip": change.get("ip", ""),
            "dest_ip": "",
            "description": (
                f"ARP MAC change for {change.get('ip', '?')}: "
                f"{change.get('old_mac', '?')} -> {change.get('new_mac', '?')}"
            ),
            "raw_details": json.dumps(change),
        }
        self._on_security_event(event)

    # ── DNS View ──────────────────────────────────────────────

    def _init_dns_view(self):
        """Load initial DNS history data."""
        self._window.dns_view.refresh()

    # ── Security Score ─────────────────────────────────────────

    def _init_security_score_timer(self):
        """Periodically recalculate the dashboard security score."""
        self._security_score_timer = QTimer()
        self._security_score_timer.setInterval(10_000)
        self._security_score_timer.timeout.connect(self._update_security_score)
        self._security_score_timer.start()
        # Initial update
        self._update_security_score()

    def _update_security_score(self):
        """Calculate security score (0-100) based on recent events and state."""
        score = 100

        # Deduct for critical and warning security events in last 24h
        counts = db.get_security_event_counts_24h()
        critical_24h = counts.get("critical", 0)
        warning_24h = counts.get("warning", 0)
        score -= min(30, critical_24h * 3)
        score -= min(20, warning_24h * 1)

        # Deduct for rogue (untrusted) devices
        trusted = db.get_trusted_macs()
        from src.utils.db import get_baseline_devices
        baseline = get_baseline_devices()
        rogue_count = sum(
            1 for d in baseline if d["mac"] not in trusted
        )
        score -= min(20, rogue_count * 5)

        score = max(0, score)
        self._window.dashboard_view.update_security_score(score)

        # Update 24h timeline
        self._update_security_timeline()

        # Update traffic heatmap
        self._update_traffic_heatmap()

        # Update threat dashboard
        self._update_threat_dashboard()

    def _update_security_timeline(self):
        """Fetch hourly event counts for the last 24 hours and update dashboard."""
        from datetime import datetime, timedelta

        now = datetime.now()
        # Build hourly buckets for last 24 hours
        hourly_data = []
        all_events = db.get_recent_security_events(1000)

        for i in range(24):
            hour_start = now - timedelta(hours=23 - i)
            hour_end = now - timedelta(hours=22 - i) if i < 23 else now
            bucket = {"hour": hour_start.hour, "critical": 0, "warning": 0, "info": 0}

            for ev in all_events:
                ts_str = ev.get("timestamp", "")
                if not ts_str:
                    continue
                try:
                    ts = datetime.fromisoformat(ts_str)
                except (ValueError, TypeError):
                    continue
                if hour_start <= ts < hour_end:
                    sev = ev.get("severity", "info")
                    if sev in bucket:
                        bucket[sev] += 1

            hourly_data.append(bucket)

        self._window.dashboard_view.update_security_timeline(hourly_data)

    def _update_traffic_heatmap(self):
        """Update the dashboard traffic heatmap from bandwidth history."""
        try:
            heatmap_data = db.get_bandwidth_heatmap_data()
            self._window.dashboard_view.update_traffic_heatmap(heatmap_data)
        except Exception:
            pass

    def _update_threat_dashboard(self):
        """Update the active threat dashboard in Security Events tab."""
        try:
            counts = db.get_security_event_counts_24h()
            critical_24h = counts.get("critical", 0)
            warning_24h = counts.get("warning", 0)
            total_24h = critical_24h + warning_24h + counts.get("info", 0)

            # Determine threat level
            if critical_24h > 0:
                level = "critical"
            elif warning_24h > 3:
                level = "elevated"
            else:
                level = "safe"

            # Count unique external IPs from current capture
            external_ips = 0
            if hasattr(self._capture_worker, "get_captured_packets"):
                geoip = self._capture_worker.get_geoip()
                seen = set()
                for p in self._capture_worker.get_captured_packets()[-500:]:
                    for key in ("src", "dst"):
                        ip = p.get(key, "")
                        if ip and not geoip.is_private(ip) and ip not in seen:
                            seen.add(ip)
                            external_ips += 1

            dashboard = self._window.security_events_view.threat_dashboard
            dashboard.update_threat_level(level)
            dashboard.update_stats(
                external_ips=external_ips,
                unresolved=critical_24h + warning_24h,
                events_24h=total_24h,
            )
        except Exception:
            pass

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
        """Clear all alerts from UI, database, and reset dashboard counter."""
        db.clear_alerts()
        self._window.alerts_view.clear_alerts()
        self._window.dashboard_view.update_alert_count(0)
        # Reset alert engine so conditions can re-fire if still active
        self._alert_engine.reset()

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
        if hasattr(self, "_conn_tracker"):
            self._conn_tracker.stop()
        if hasattr(self, "_baseline"):
            self._baseline.stop()
        if hasattr(self, "_arp_monitor"):
            self._arp_monitor.stop()
        if hasattr(self, "_top_talkers_timer"):
            self._top_talkers_timer.stop()
        if hasattr(self, "_security_score_timer"):
            self._security_score_timer.stop()
