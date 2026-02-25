"""Packet capture with Deep Packet Inspection integration."""

from datetime import datetime

from PySide6.QtCore import Signal, QThread

from src.core.dpi import analyze_packet


class PacketCaptureWorker(QThread):
    """Captures packets using scapy's AsyncSniffer with DPI enrichment."""

    packet_captured = Signal(dict)     # DPI-enriched packet info for GUI
    raw_packet_data = Signal(dict)     # Raw+DPI data for IDS/flow/SET defense
    dns_packet = Signal(dict)          # DNS-specific data for DNS monitor
    capture_status = Signal(str)
    proto_stats = Signal(float, float, float)  # tcp_ps, udp_ps, other_ps
    app_proto_stats = Signal(dict)     # Per-app-protocol counts

    def __init__(self, bpf_filter: str = "", parent=None):
        super().__init__(parent)
        self._filter = bpf_filter
        self._running = False
        self._sniffer = None
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
        self._app_proto_counts: dict[str, int] = {}
        self._last_stats_time = None

    def set_filter(self, bpf_filter: str):
        self._filter = bpf_filter

    def run(self):
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP
        except ImportError:
            self.capture_status.emit("scapy not installed")
            return

        self._running = True
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
        self._app_proto_counts = {}
        self._last_stats_time = datetime.now()
        self.capture_status.emit("Capturing...")

        def process_packet(pkt):
            if not self._running:
                return

            info = {
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": "",
                "dst": "",
                "protocol": "Other",
                "length": len(pkt),
                "info": pkt.summary() if hasattr(pkt, "summary") else str(pkt)[:80],
                "tcp_flags": "",
            }

            if IP in pkt:
                info["src"] = pkt[IP].src
                info["dst"] = pkt[IP].dst
                if TCP in pkt:
                    info["protocol"] = "TCP"
                    info["tcp_flags"] = str(pkt[TCP].flags)
                    info["info"] = f":{pkt[TCP].sport} -> :{pkt[TCP].dport} [{pkt[TCP].flags}]"
                    self._tcp_count += 1
                elif UDP in pkt:
                    info["protocol"] = "UDP"
                    info["info"] = f":{pkt[UDP].sport} -> :{pkt[UDP].dport}"
                    self._udp_count += 1
                else:
                    self._other_count += 1
            elif ARP in pkt:
                info["protocol"] = "ARP"
                info["src"] = pkt[ARP].psrc
                info["dst"] = pkt[ARP].pdst
                self._other_count += 1
            else:
                self._other_count += 1

            # ── Deep Packet Inspection ────────────────────────
            try:
                dpi_result = analyze_packet(pkt)
                info.update({
                    "app_protocol": dpi_result.get("app_protocol", ""),
                    "app_details": dpi_result.get("app_details", ""),
                    "threat_flags": dpi_result.get("threat_flags", []),
                    "payload_hex": dpi_result.get("payload_hex", ""),
                    "payload_ascii": dpi_result.get("payload_ascii", ""),
                    "tls_sni": dpi_result.get("tls_sni", ""),
                    "dns_query": dpi_result.get("dns_query", ""),
                    "dns_response": dpi_result.get("dns_response", ""),
                    "dns_qtype": dpi_result.get("dns_qtype", ""),
                    "dns_rcode": dpi_result.get("dns_rcode", ""),
                    "http_method": dpi_result.get("http_method", ""),
                    "http_host": dpi_result.get("http_host", ""),
                    "http_uri": dpi_result.get("http_uri", ""),
                    "ssh_banner": dpi_result.get("ssh_banner", ""),
                    "src_port": dpi_result.get("src_port", 0),
                    "dst_port": dpi_result.get("dst_port", 0),
                })

                # ARP-specific fields for IDS
                if ARP in pkt:
                    info["arp_src_ip"] = pkt[ARP].psrc
                    info["arp_src_mac"] = pkt[ARP].hwsrc
                    info["arp_dst_ip"] = pkt[ARP].pdst
                    info["arp_dst_mac"] = pkt[ARP].hwdst

                # Track app protocol stats
                app_proto = dpi_result.get("app_protocol", "")
                if app_proto:
                    self._app_proto_counts[app_proto] = self._app_proto_counts.get(app_proto, 0) + 1

                # Update info line with DPI details if available
                dpi_details = dpi_result.get("app_details", "")
                if dpi_details:
                    info["info"] = dpi_details

            except Exception:
                info["app_protocol"] = ""
                info["app_details"] = ""
                info["threat_flags"] = []

            # Emit enriched packet to GUI
            self.packet_captured.emit(info)

            # Emit raw data to IDS/flow tracker/SET defense
            self.raw_packet_data.emit(info)

            # Emit DNS-specific data to DNS monitor
            if info.get("app_protocol") == "DNS" and info.get("dns_query"):
                self.dns_packet.emit(info)

            # Emit stats every second
            now = datetime.now()
            elapsed = (now - self._last_stats_time).total_seconds()
            if elapsed >= 1.0:
                self.proto_stats.emit(
                    self._tcp_count / elapsed,
                    self._udp_count / elapsed,
                    self._other_count / elapsed,
                )
                self._tcp_count = 0
                self._udp_count = 0
                self._other_count = 0
                self._last_stats_time = now

                # Emit app protocol stats
                if self._app_proto_counts:
                    self.app_proto_stats.emit(dict(self._app_proto_counts))

        kwargs = {"prn": process_packet, "store": False}
        if self._filter:
            kwargs["filter"] = self._filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

        # Keep thread alive while sniffer runs
        while self._running:
            self.msleep(100)

        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        self.capture_status.emit("Stopped")

    def stop(self):
        self._running = False
        self.wait(5000)
