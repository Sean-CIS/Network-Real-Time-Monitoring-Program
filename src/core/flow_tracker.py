"""Network Flow Tracker — tracks conversations, top talkers, protocol distribution."""

import time
from collections import defaultdict
from datetime import datetime

from PySide6.QtCore import QObject, Signal, QTimer


class Flow:
    """Represents a single network conversation."""
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "app_protocol", "start_time", "last_seen", "bytes_sent",
                 "bytes_recv", "packets", "state")

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.app_protocol = ""
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.packets = 0
        self.state = "active"

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol, "app_protocol": self.app_protocol,
            "start_time": self.start_time, "last_seen": self.last_seen,
            "bytes_sent": self.bytes_sent, "bytes_recv": self.bytes_recv,
            "packets": self.packets, "duration": self.duration,
            "state": self.state,
        }


class FlowTracker(QObject):
    """Tracks network flows and emits aggregated statistics."""

    flow_stats_updated = Signal(dict)

    IDLE_TIMEOUT = 30.0  # seconds before a flow is considered idle

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: dict[tuple, Flow] = {}
        self._total_new = 0
        self._total_closed = 0

        # Stats emission timer
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(2000)
        self._stats_timer.timeout.connect(self._emit_stats)
        self._stats_timer.start()

    def process_packet(self, pkt_info: dict):
        """Process a DPI-enriched packet to update flow state."""
        src_ip = pkt_info.get("src", "")
        dst_ip = pkt_info.get("dst", "")
        src_port = pkt_info.get("src_port", 0)
        dst_port = pkt_info.get("dst_port", 0)
        protocol = pkt_info.get("protocol", "OTHER")
        app_protocol = pkt_info.get("app_protocol", "")
        length = pkt_info.get("length", 0)

        if not src_ip or not dst_ip:
            return

        # Create flow key (bidirectional — normalize by sorting)
        key_fwd = (src_ip, src_port, dst_ip, dst_port, protocol)
        key_rev = (dst_ip, dst_port, src_ip, src_port, protocol)

        now = time.time()

        if key_fwd in self._flows:
            flow = self._flows[key_fwd]
            flow.bytes_sent += length
            flow.packets += 1
            flow.last_seen = now
            if app_protocol and not flow.app_protocol:
                flow.app_protocol = app_protocol
        elif key_rev in self._flows:
            flow = self._flows[key_rev]
            flow.bytes_recv += length
            flow.packets += 1
            flow.last_seen = now
        else:
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
            flow.bytes_sent = length
            flow.packets = 1
            flow.app_protocol = app_protocol
            self._flows[key_fwd] = flow
            self._total_new += 1

    def _emit_stats(self):
        """Compute and emit aggregated flow statistics."""
        now = time.time()

        # Prune idle/closed flows
        to_remove = []
        for key, flow in self._flows.items():
            if now - flow.last_seen > self.IDLE_TIMEOUT:
                flow.state = "closed"
                to_remove.append(key)

        for key in to_remove:
            del self._flows[key]
            self._total_closed += 1

        active_flows = list(self._flows.values())

        # ── Top Talkers (by host) ────────────────────────────
        host_bytes: dict[str, dict] = defaultdict(
            lambda: {"bytes_sent": 0, "bytes_recv": 0, "flow_count": 0, "protocol": ""}
        )
        for flow in active_flows:
            h = host_bytes[flow.src_ip]
            h["bytes_sent"] += flow.bytes_sent
            h["bytes_recv"] += flow.bytes_recv
            h["flow_count"] += 1
            if flow.app_protocol:
                h["protocol"] = flow.app_protocol

            h2 = host_bytes[flow.dst_ip]
            h2["bytes_recv"] += flow.bytes_sent
            h2["bytes_sent"] += flow.bytes_recv
            h2["flow_count"] += 1

        top_talkers = sorted(
            [{"ip": ip, **data, "total": data["bytes_sent"] + data["bytes_recv"]}
             for ip, data in host_bytes.items()],
            key=lambda x: x["total"], reverse=True
        )[:20]

        # ── Top Flows ────────────────────────────────────────
        top_flows = sorted(
            [flow.to_dict() for flow in active_flows],
            key=lambda x: x["bytes_sent"] + x["bytes_recv"], reverse=True
        )[:20]

        # ── Protocol Distribution ────────────────────────────
        proto_bytes: dict[str, int] = defaultdict(int)
        for flow in active_flows:
            proto = flow.app_protocol or flow.protocol
            proto_bytes[proto] += flow.total_bytes

        # ── Unique external IPs ──────────────────────────────
        external_ips = set()
        for flow in active_flows:
            for ip in (flow.src_ip, flow.dst_ip):
                if ip and not ip.startswith(("10.", "192.168.", "172.16.", "127.")):
                    external_ips.add(ip)

        stats = {
            "active_flows": len(active_flows),
            "total_new": self._total_new,
            "total_closed": self._total_closed,
            "top_talkers": top_talkers,
            "top_flows": top_flows,
            "protocol_distribution": dict(proto_bytes),
            "external_ips": len(external_ips),
        }

        self.flow_stats_updated.emit(stats)
