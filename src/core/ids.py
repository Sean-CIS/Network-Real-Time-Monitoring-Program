"""Intrusion Detection System — real-time threat detection from packet stream."""

import time
from collections import defaultdict, deque
from datetime import datetime

from PySide6.QtCore import QObject, Signal


class IntrusionDetectionSystem(QObject):
    """Analyzes packets for intrusion patterns and emits security events."""

    security_event = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        # Sliding window trackers
        self._port_scans: dict[str, deque] = defaultdict(lambda: deque())  # src_ip → deque of (ts, dst_port)
        self._net_sweeps: dict[str, deque] = defaultdict(lambda: deque())  # src_ip → deque of (ts, dst_ip)
        self._syn_floods: dict[str, deque] = defaultdict(lambda: deque())  # src_ip → deque of timestamps
        self._brute_force: dict[str, deque] = defaultdict(lambda: deque())  # src_ip:port → deque of timestamps
        self._data_transfer: dict[tuple, int] = defaultdict(int)  # (src, dst) → bytes
        self._data_transfer_ts: dict[tuple, float] = {}
        self._icmp_payloads: dict[str, deque] = defaultdict(lambda: deque())  # src_ip → deque of (ts, size)
        self._arp_table: dict[str, str] = {}  # ip → mac
        self._cooldowns: dict[str, float] = {}
        self._cooldown_s = 60.0  # min seconds between same alert from same source

        # Thresholds
        self._port_scan_threshold = 15
        self._port_scan_critical = 50
        self._net_sweep_threshold = 20
        self._syn_flood_threshold = 50
        self._brute_force_threshold = 10
        self._data_exfil_bytes = 50 * 1024 * 1024  # 50MB
        self._icmp_tunnel_avg = 100  # avg bytes

        # Suspicious ports
        self._suspicious_ports = {4444, 5555, 6666, 6667, 31337, 1337, 9001, 12345, 54321}
        self._auth_ports = {22, 23, 3389, 5900, 21}

    def configure(self, **kwargs):
        for key, val in kwargs.items():
            attr = f"_{key}"
            if hasattr(self, attr):
                setattr(self, attr, val)

    def process_packet(self, pkt_info: dict):
        """Process a DPI-enriched packet dict for threat detection."""
        try:
            self._check_all_rules(pkt_info)
        except Exception:
            pass

    def _check_all_rules(self, info: dict):
        now = time.time()
        src_ip = info.get("src", "")
        dst_ip = info.get("dst", "")
        src_port = info.get("src_port", 0)
        dst_port = info.get("dst_port", 0)
        protocol = info.get("protocol", "")
        app_protocol = info.get("app_protocol", "")
        flags = info.get("tcp_flags", "")
        length = info.get("length", 0)

        # ── Rule 1: Port Scan Detection ──────────────────────
        if src_ip and dst_port:
            tracker = self._port_scans[src_ip]
            tracker.append((now, dst_port))
            self._prune_window(tracker, now, 60)
            unique_ports = len(set(p for _, p in tracker))
            if unique_ports > self._port_scan_critical:
                self._emit("port_scan", "critical", "Port Scan Detected",
                           f"{src_ip} probed {unique_ports} ports in 60s",
                           src_ip, dst_ip, src_port, dst_port,
                           f"Unique ports: {unique_ports}", "Block source IP")
            elif unique_ports > self._port_scan_threshold:
                self._emit("port_scan", "warning", "Port Scan Detected",
                           f"{src_ip} probed {unique_ports} ports in 60s",
                           src_ip, dst_ip, src_port, dst_port,
                           f"Unique ports: {unique_ports}", "Monitor source IP")

        # ── Rule 2: Network Sweep Detection ──────────────────
        if src_ip and dst_ip:
            tracker = self._net_sweeps[src_ip]
            tracker.append((now, dst_ip))
            self._prune_window(tracker, now, 60)
            unique_ips = len(set(ip for _, ip in tracker))
            if unique_ips > self._net_sweep_threshold:
                self._emit("net_sweep", "warning", "Network Sweep Detected",
                           f"{src_ip} contacted {unique_ips} unique IPs in 60s",
                           src_ip, "", src_port, 0,
                           f"Unique targets: {unique_ips}", "Investigate source")

        # ── Rule 3: ARP Spoofing Detection ───────────────────
        if app_protocol == "ARP":
            arp_details = info.get("app_details", "")
            if "reply" in arp_details.lower():
                # Extract sender IP and MAC from ARP details
                arp_src_ip = info.get("arp_src_ip", "")
                arp_src_mac = info.get("arp_src_mac", "")
                if arp_src_ip and arp_src_mac:
                    if arp_src_ip in self._arp_table:
                        if self._arp_table[arp_src_ip] != arp_src_mac:
                            old_mac = self._arp_table[arp_src_ip]
                            self._emit("arp_spoof", "critical", "ARP Spoofing Detected",
                                       f"IP {arp_src_ip} changed MAC from {old_mac} to {arp_src_mac}",
                                       arp_src_ip, "", 0, 0,
                                       f"Old MAC: {old_mac}, New MAC: {arp_src_mac}",
                                       "Isolate affected hosts, verify ARP tables")
                    self._arp_table[arp_src_ip] = arp_src_mac

        # ── Rule 4: SYN Flood Detection ──────────────────────
        if protocol == "TCP" and "S" in flags and "A" not in flags:
            tracker = self._syn_floods[src_ip]
            tracker.append(now)
            self._prune_window_simple(tracker, now, 10)
            if len(tracker) > self._syn_flood_threshold:
                self._emit("syn_flood", "critical", "SYN Flood Detected",
                           f"{len(tracker)} SYN packets from {src_ip} in 10s",
                           src_ip, dst_ip, src_port, dst_port,
                           f"SYN count: {len(tracker)}", "Enable SYN cookies, rate limit source")

        # ── Rule 5: DNS Tunneling Detection ──────────────────
        if app_protocol == "DNS":
            dns_query = info.get("dns_query", "")
            threat_flags = info.get("threat_flags", [])
            if "long_dns_query" in threat_flags:
                self._emit("dns_tunnel", "warning", "Possible DNS Tunneling",
                           f"Unusually long DNS query from {src_ip}: {dns_query[:60]}...",
                           src_ip, dst_ip, src_port, dst_port,
                           f"Query length: {len(dns_query)}", "Inspect DNS traffic from source")
            if "dns_txt_query" in threat_flags:
                self._emit("dns_txt_abuse", "info", "DNS TXT Query",
                           f"TXT record query from {src_ip}: {dns_query[:60]}",
                           src_ip, dst_ip, src_port, dst_port,
                           "TXT queries can be used for tunneling", "Monitor frequency")

        # ── Rule 6: Brute Force Detection ────────────────────
        if dst_port in self._auth_ports:
            key = f"{src_ip}:{dst_port}"
            tracker = self._brute_force[key]
            tracker.append(now)
            self._prune_window_simple(tracker, now, 60)
            if len(tracker) > self._brute_force_threshold:
                svc = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 21: "FTP"}.get(dst_port, str(dst_port))
                self._emit("brute_force", "warning", "Brute Force Attempt",
                           f"{len(tracker)} connections from {src_ip} to {svc} (port {dst_port}) in 60s",
                           src_ip, dst_ip, src_port, dst_port,
                           f"Attempts: {len(tracker)}", f"Block {src_ip} on port {dst_port}")

        # ── Rule 7: Large Data Transfer ──────────────────────
        if src_ip and dst_ip and length > 0:
            flow_key = (src_ip, dst_ip)
            if flow_key not in self._data_transfer_ts:
                self._data_transfer_ts[flow_key] = now
            self._data_transfer[flow_key] += length
            elapsed = now - self._data_transfer_ts[flow_key]
            if elapsed > 300:  # Reset after 5 min window
                self._data_transfer[flow_key] = length
                self._data_transfer_ts[flow_key] = now
            if self._data_transfer[flow_key] > self._data_exfil_bytes:
                mb = self._data_transfer[flow_key] / (1024 * 1024)
                self._emit("data_exfil", "warning", "Large Data Transfer",
                           f"{mb:.1f} MB transferred from {src_ip} to {dst_ip} in {elapsed:.0f}s",
                           src_ip, dst_ip, src_port, dst_port,
                           f"Bytes: {self._data_transfer[flow_key]}", "Verify authorized transfer")
                self._data_transfer[flow_key] = 0  # Reset after alert

        # ── Rule 8: Suspicious Port Activity ─────────────────
        if dst_port in self._suspicious_ports or src_port in self._suspicious_ports:
            port = dst_port if dst_port in self._suspicious_ports else src_port
            self._emit("suspicious_port", "warning", "Suspicious Port Activity",
                       f"Traffic on port {port}: {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                       src_ip, dst_ip, src_port, dst_port,
                       f"Port {port} is commonly used by malware/C2", "Investigate process using port")

        # ── Rule 9: Cleartext Credentials ────────────────────
        threat_flags = info.get("threat_flags", [])
        if "cleartext_auth" in threat_flags:
            self._emit("cleartext_auth", "info", "Cleartext Authentication Detected",
                       f"Unencrypted credentials on {app_protocol} from {src_ip} to {dst_ip}:{dst_port}",
                       src_ip, dst_ip, src_port, dst_port,
                       f"Protocol: {app_protocol}", "Use encrypted protocol (TLS/SSH)")

        # ── Rule 10: ICMP Tunnel Detection ───────────────────
        if app_protocol == "ICMP" and "icmp_large_payload" in threat_flags:
            tracker = self._icmp_payloads[src_ip]
            tracker.append((now, length))
            self._prune_window(tracker, now, 60)
            if len(tracker) > 5:
                avg_size = sum(s for _, s in tracker) / len(tracker)
                if avg_size > self._icmp_tunnel_avg:
                    self._emit("icmp_tunnel", "warning", "Possible ICMP Tunnel",
                               f"Large ICMP payloads from {src_ip} (avg {avg_size:.0f} bytes)",
                               src_ip, dst_ip, 0, 0,
                               f"Avg payload: {avg_size:.0f} bytes", "Block ICMP or inspect")

        # ── Rule 11: Weak TLS ────────────────────────────────
        if "weak_tls" in threat_flags:
            tls_ver = info.get("tls_version", "")
            self._emit("weak_tls", "info", "Weak TLS Version",
                       f"Connection using {tls_ver} from {src_ip} to {dst_ip}:{dst_port}",
                       src_ip, dst_ip, src_port, dst_port,
                       f"TLS version: {tls_ver}", "Upgrade to TLS 1.2+")

    def _prune_window(self, tracker: deque, now: float, window_s: float):
        while tracker and now - tracker[0][0] > window_s:
            tracker.popleft()

    def _prune_window_simple(self, tracker: deque, now: float, window_s: float):
        while tracker and now - tracker[0] > window_s:
            tracker.popleft()

    def _emit(self, rule_id: str, severity: str, title: str, description: str,
              src_ip: str = "", dst_ip: str = "", src_port: int = 0, dst_port: int = 0,
              evidence: str = "", recommended_action: str = ""):
        key = f"{rule_id}:{src_ip}"
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self._cooldown_s:
            return
        self._cooldowns[key] = now

        self.security_event.emit({
            "timestamp": datetime.now().isoformat(),
            "rule_id": rule_id,
            "severity": severity,
            "title": title,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "evidence": evidence,
            "recommended_action": recommended_action,
        })
