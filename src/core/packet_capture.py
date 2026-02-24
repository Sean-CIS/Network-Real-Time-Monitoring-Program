"""Packet capture worker with integrated threat detection, GeoIP, and protocol analysis."""

import time
from datetime import datetime

from PySide6.QtCore import Signal, QThread

from src.core.geoip import GeoIPLookup
from src.core.protocol_analyzer import ProtocolAnalyzer
from src.core.threat_detector import ThreatDetector
from src.utils import db

_MAX_RAW_PACKETS = 100_000


class PacketCaptureWorker(QThread):
    """Captures packets using scapy's AsyncSniffer with security analysis."""

    packet_captured = Signal(dict)
    capture_status = Signal(str)
    proto_stats = Signal(float, float, float)  # tcp_ps, udp_ps, other_ps
    protocol_dist = Signal(dict)               # app protocol distribution
    security_event = Signal(dict)

    def __init__(self, bpf_filter: str = "", parent=None):
        super().__init__(parent)
        self._filter = bpf_filter
        self._running = False
        self._sniffer = None
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
        self._last_stats_time = None

        # Security analysis
        self._threat_detector = ThreatDetector()
        self._geoip = GeoIPLookup()
        self._protocol_analyzer = ProtocolAnalyzer()

        # Process attribution cache
        self._conn_process_map: dict[tuple, str] = {}
        self._last_process_refresh: float = 0.0

        # Stored data for export/report
        self._raw_packets: list = []
        self._captured_packets: list[dict] = []
        self._security_events: list[dict] = []
        self._capture_start_time: datetime | None = None
        self._capture_duration_s: float = 0.0
        self._total_bytes: int = 0

    def set_filter(self, bpf_filter: str):
        self._filter = bpf_filter

    def _refresh_process_map(self):
        """Refresh connection->process mapping from psutil every 5 seconds."""
        now = time.time()
        if now - self._last_process_refresh < 5.0:
            return
        self._last_process_refresh = now
        try:
            import psutil
            self._conn_process_map.clear()
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and c.pid:
                    try:
                        proc = psutil.Process(c.pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied,
                            psutil.ZombieProcess):
                        name = ""
                    if name:
                        key = (c.laddr.ip, c.laddr.port)
                        self._conn_process_map[key] = name
        except Exception:
            pass

    def _lookup_process(self, src: str, src_port, dst: str, dst_port) -> str:
        """Look up process name for a connection by local address/port."""
        self._refresh_process_map()
        if src_port:
            proc = self._conn_process_map.get((src, src_port))
            if proc:
                return proc
        if dst_port:
            proc = self._conn_process_map.get((dst, dst_port))
            if proc:
                return proc
        return ""

    def analyze_single_packet(self, pkt) -> dict:
        """Analyze a single scapy packet and return info dict.

        Can be called externally for PCAP replay without running the sniffer.
        """
        try:
            from scapy.all import IP, TCP, UDP, ARP, DNS
        except ImportError:
            return {}

        pkt_len = len(pkt)

        info = {
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": "",
            "dst": "",
            "protocol": "Other",
            "length": pkt_len,
            "info": pkt.summary() if hasattr(pkt, "summary") else str(pkt)[:80],
            "tcp_flags": "",
            "src_port": None,
            "dst_port": None,
            "threat_level": "",
            "country_src": "",
            "country_dst": "",
            "process": "",
            "protocol_detail": "",
            "sni": "",
        }

        if IP in pkt:
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst

            if TCP in pkt:
                info["protocol"] = "TCP"
                flags = str(pkt[TCP].flags)
                info["tcp_flags"] = flags
                info["src_port"] = pkt[TCP].sport
                info["dst_port"] = pkt[TCP].dport
                info["info"] = f":{pkt[TCP].sport} -> :{pkt[TCP].dport} [{flags}]"
            elif UDP in pkt:
                info["protocol"] = "UDP"
                info["src_port"] = pkt[UDP].sport
                info["dst_port"] = pkt[UDP].dport
                info["info"] = f":{pkt[UDP].sport} -> :{pkt[UDP].dport}"

                # Add DNS query info
                if DNS in pkt and pkt[DNS].qd:
                    try:
                        qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        info["info"] += f" DNS {qname}"
                    except (AttributeError, UnicodeDecodeError):
                        pass

            # GeoIP lookups — "Local" for private, blank for multicast, "N/A" if no DB
            for key, addr_key in (("country_src", "src"), ("country_dst", "dst")):
                addr = info[addr_key]
                if not addr:
                    continue
                if self._geoip.is_private(addr):
                    info[key] = "Local"
                elif self._geoip.is_multicast(addr):
                    info[key] = ""
                else:
                    geo = self._geoip.lookup(addr)
                    cc = geo.get("country_code", "")
                    info[key] = cc if cc and cc != "?" else "N/A"
        elif ARP in pkt:
            info["protocol"] = "ARP"
            info["src"] = pkt[ARP].psrc
            info["dst"] = pkt[ARP].pdst

        # Protocol deep inspection
        proto_detail = self._protocol_analyzer.analyze(pkt)
        if proto_detail:
            detail_str = proto_detail.get("detail", "")
            if detail_str:
                info["protocol_detail"] = detail_str
                info["info"] = detail_str
            sni = proto_detail.get("sni", "")
            if sni:
                info["sni"] = sni

        # Process attribution
        info["process"] = self._lookup_process(
            info["src"], info.get("src_port"),
            info["dst"], info.get("dst_port"),
        )

        # DNS logging to history
        if proto_detail.get("app_protocol") == "DNS":
            self._log_dns(proto_detail, info["src"])

        return info

    def _log_dns(self, proto_detail: dict, source_ip: str):
        """Log DNS query/response to the dns_history table."""
        try:
            db.insert_dns_record(
                query=proto_detail.get("dns_query", ""),
                query_type=proto_detail.get("dns_type", ""),
                response=proto_detail.get("dns_response", ""),
                ttl=0,
                source_ip=source_ip,
            )
        except Exception:
            pass

    def run(self):
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP, DNS
        except ImportError:
            self.capture_status.emit("scapy not installed")
            return

        self._running = True
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
        self._last_stats_time = datetime.now()
        self._capture_start_time = datetime.now()
        self._raw_packets.clear()
        self._captured_packets.clear()
        self._security_events.clear()
        self._threat_detector.reset()
        self._protocol_analyzer.reset()
        self._total_bytes = 0
        self.capture_status.emit("Capturing...")

        def process_packet(pkt):
            if not self._running:
                return

            pkt_len = len(pkt)
            self._total_bytes += pkt_len

            # Count transport-layer protocol
            if IP in pkt:
                if TCP in pkt:
                    self._tcp_count += 1
                elif UDP in pkt:
                    self._udp_count += 1
                else:
                    self._other_count += 1
            else:
                self._other_count += 1

            # Full analysis via the shared method
            info = self.analyze_single_packet(pkt)

            # Run threat detection
            events = self._threat_detector.analyze_packet(info, pkt)
            if events:
                severities = [e["severity"] for e in events]
                if "critical" in severities:
                    info["threat_level"] = "critical"
                elif "warning" in severities:
                    info["threat_level"] = "warning"
                else:
                    info["threat_level"] = "info"

                for event in events:
                    self._security_events.append(event)
                    self.security_event.emit(event)

            # Store for export
            if len(self._raw_packets) < _MAX_RAW_PACKETS:
                self._raw_packets.append(pkt)
            self._captured_packets.append(info)

            self.packet_captured.emit(info)

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

                # Emit protocol distribution
                self.protocol_dist.emit(self._protocol_analyzer.protocol_counts)

        kwargs = {"prn": process_packet, "store": False}
        if self._filter:
            kwargs["filter"] = self._filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

        # Keep thread alive while sniffer runs
        while self._running:
            self.msleep(100)

        self._capture_duration_s = (
            (datetime.now() - self._capture_start_time).total_seconds()
            if self._capture_start_time else 0.0
        )

        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        self.capture_status.emit("Stopped")

    def stop(self):
        self._running = False
        self.wait(5000)

    # ── Data access for exports/reports ──────────────────────

    def get_raw_packets(self) -> list:
        """Return stored raw scapy packets for PCAP export."""
        return list(self._raw_packets)

    def get_captured_packets(self) -> list[dict]:
        """Return stored packet dicts for CSV/report."""
        return list(self._captured_packets)

    def get_capture_metadata(self) -> dict:
        return {
            "start_time": self._capture_start_time.isoformat() if self._capture_start_time else "",
            "duration_s": self._capture_duration_s,
            "filter": self._filter,
            "total_packets": len(self._captured_packets),
            "total_bytes": self._total_bytes,
            "proto_counts": {
                "TCP": sum(1 for p in self._captured_packets if p.get("protocol") == "TCP"),
                "UDP": sum(1 for p in self._captured_packets if p.get("protocol") == "UDP"),
                "Other": sum(1 for p in self._captured_packets if p.get("protocol") not in ("TCP", "UDP")),
            },
        }

    def get_top_talkers(self, limit: int = 10) -> list[dict]:
        return self._threat_detector.get_top_talkers(limit)

    def get_security_events(self) -> list[dict]:
        return list(self._security_events)

    def get_geoip(self) -> GeoIPLookup:
        return self._geoip

    def get_protocol_counts(self) -> dict[str, int]:
        return self._protocol_analyzer.protocol_counts
