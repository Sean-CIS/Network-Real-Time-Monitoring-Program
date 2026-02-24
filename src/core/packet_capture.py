from datetime import datetime

from PySide6.QtCore import Signal, QThread


class PacketCaptureWorker(QThread):
    """Captures packets using scapy's AsyncSniffer."""

    packet_captured = Signal(dict)
    capture_status = Signal(str)
    proto_stats = Signal(float, float, float)  # tcp_ps, udp_ps, other_ps

    def __init__(self, bpf_filter: str = "", parent=None):
        super().__init__(parent)
        self._filter = bpf_filter
        self._running = False
        self._sniffer = None
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
        self._last_stats_time = None

    def set_filter(self, bpf_filter: str):
        self._filter = bpf_filter

    def run(self):
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP
        except ImportError:
            self.capture_status.emit("scapy not installed")
            return

        self._running = True
        self._tcp_count = 0
        self._udp_count = 0
        self._other_count = 0
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
            }

            if IP in pkt:
                info["src"] = pkt[IP].src
                info["dst"] = pkt[IP].dst
                if TCP in pkt:
                    info["protocol"] = "TCP"
                    info["info"] = f":{pkt[TCP].sport} -> :{pkt[TCP].dport} [{pkt[TCP].flags}]"
                    self._tcp_count += 1
                elif UDP in pkt:
                    info["protocol"] = "UDP"
                    info["info"] = f":{pkt[UDP].sport} -> :{pkt[UDP].dport}"
                    self._udp_count += 1
                else:
                    self._other_count += 1
            else:
                self._other_count += 1

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
