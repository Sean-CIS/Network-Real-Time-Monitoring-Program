"""Interactive force-directed network topology graph using QPainter."""

import math
import random
import numpy as np
from PySide6.QtCore import Qt, QPointF, QRectF, QTimer
from PySide6.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QPainterPath,
    QRadialGradient, QLinearGradient,
)
from PySide6.QtWidgets import QWidget, QToolTip


# Device type classification
DEVICE_TYPES = {
    "router": {"color": "#f9e2af", "icon": "R", "size": 22},
    "server": {"color": "#89b4fa", "icon": "S", "size": 20},
    "computer": {"color": "#a6e3a1", "icon": "C", "size": 18},
    "phone": {"color": "#cba6f7", "icon": "P", "size": 16},
    "printer": {"color": "#94e2d5", "icon": "Pr", "size": 16},
    "unknown": {"color": "#cdd6f4", "icon": "?", "size": 16},
}


def classify_device(device: dict) -> str:
    """Heuristic device type classification."""
    ip = device.get("ip", "")
    vendor = device.get("vendor", "").lower()
    hostname = device.get("hostname", "").lower()
    os_info = device.get("os_info", "").lower()

    # Gateway / router detection
    if ip.endswith(".1") or ip.endswith(".254"):
        return "router"
    if any(kw in vendor for kw in ("cisco", "netgear", "linksys", "tp-link", "asus",
                                    "ubiquiti", "mikrotik", "aruba", "juniper")):
        return "router"
    if "network equipment" in os_info:
        return "router"

    # Phone / mobile
    if any(kw in vendor for kw in ("apple", "samsung", "huawei", "xiaomi", "oneplus", "google")):
        if "phone" in hostname or "iphone" in hostname or "android" in hostname:
            return "phone"

    # Printer
    if any(kw in vendor for kw in ("hp", "epson", "canon", "brother", "lexmark")):
        return "printer"
    if "printer" in hostname or "print" in hostname:
        return "printer"

    # Server
    if "server" in hostname or "nas" in hostname or "docker" in hostname:
        return "server"

    # Computer (default for identifiable devices)
    if os_info or hostname:
        return "computer"

    return "unknown"


class TopologyNode:
    """Represents a device node in the topology."""

    def __init__(self, device_id: str, label: str, device_type: str = "unknown",
                 is_online: bool = True):
        self.device_id = device_id
        self.label = label
        self.device_type = device_type
        self.is_online = is_online
        self.x = random.uniform(50, 350)
        self.y = random.uniform(50, 250)
        self.vx = 0.0
        self.vy = 0.0
        self.pinned = False
        self.data: dict = {}

    @property
    def config(self) -> dict:
        return DEVICE_TYPES.get(self.device_type, DEVICE_TYPES["unknown"])


class TopologyEdge:
    """Represents a connection between two nodes."""

    def __init__(self, src_id: str, dst_id: str, weight: float = 1.0):
        self.src_id = src_id
        self.dst_id = dst_id
        self.weight = weight


class TopologyMapWidget(QWidget):
    """Interactive force-directed network topology visualization."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 280)
        self._nodes: dict[str, TopologyNode] = {}
        self._edges: list[TopologyEdge] = []
        self._dragging_node: TopologyNode | None = None
        self._drag_offset = QPointF()
        self._hover_node: TopologyNode | None = None
        self._zoom = 1.0
        self._iterations_left = 0

        self.setMouseTracking(True)

        # Layout timer
        self._layout_timer = QTimer(self)
        self._layout_timer.setInterval(33)  # ~30fps
        self._layout_timer.timeout.connect(self._layout_step)

    def set_devices(self, devices: list[dict]):
        """Update topology with discovered devices."""
        existing_ids = set(self._nodes.keys())
        new_ids = set()

        for dev in devices:
            ip = dev.get("ip", "")
            if not ip:
                continue
            new_ids.add(ip)

            if ip not in self._nodes:
                dtype = classify_device(dev)
                label = dev.get("hostname") or dev.get("ip", "")
                node = TopologyNode(ip, label, dtype, dev.get("is_online", True))
                node.data = dev
                self._nodes[ip] = node
            else:
                node = self._nodes[ip]
                node.is_online = dev.get("is_online", True)
                node.data = dev
                node.device_type = classify_device(dev)
                node.label = dev.get("hostname") or dev.get("ip", "")

        # Remove stale nodes
        for stale_id in existing_ids - new_ids:
            del self._nodes[stale_id]

        # Build star topology: all devices connect to the first router / gateway
        self._edges.clear()
        router_id = None
        for nid, node in self._nodes.items():
            if node.device_type == "router":
                router_id = nid
                break

        if router_id:
            for nid in self._nodes:
                if nid != router_id:
                    self._edges.append(TopologyEdge(router_id, nid))

        # Run layout
        self._iterations_left = 80
        if not self._layout_timer.isActive():
            self._layout_timer.start()

    def set_traffic_edges(self, edges: list[tuple[str, str, float]]):
        """Add edges from observed traffic: (src_ip, dst_ip, byte_count)."""
        existing = {(e.src_id, e.dst_id) for e in self._edges}
        for src, dst, weight in edges:
            if src in self._nodes and dst in self._nodes:
                if (src, dst) not in existing and (dst, src) not in existing:
                    self._edges.append(TopologyEdge(src, dst, weight))
                    existing.add((src, dst))

    def _layout_step(self):
        """Fruchterman-Reingold force-directed layout iteration."""
        if self._iterations_left <= 0:
            self._layout_timer.stop()
            self.update()
            return

        self._iterations_left -= 1
        nodes = list(self._nodes.values())
        n = len(nodes)
        if n < 2:
            self._layout_timer.stop()
            self.update()
            return

        w = self.width()
        h = self.height()
        area = w * h
        k = math.sqrt(area / max(n, 1)) * 0.6  # optimal distance
        temp = max(5, 50 * (self._iterations_left / 80))  # cooling

        # Repulsive forces (all pairs)
        for i in range(n):
            if nodes[i].pinned:
                continue
            fx, fy = 0.0, 0.0
            for j in range(n):
                if i == j:
                    continue
                dx = nodes[i].x - nodes[j].x
                dy = nodes[i].y - nodes[j].y
                dist = max(math.hypot(dx, dy), 1.0)
                force = (k * k) / dist
                fx += (dx / dist) * force
                fy += (dy / dist) * force
            nodes[i].vx += fx
            nodes[i].vy += fy

        # Attractive forces (edges)
        for edge in self._edges:
            src = self._nodes.get(edge.src_id)
            dst = self._nodes.get(edge.dst_id)
            if not src or not dst:
                continue
            dx = dst.x - src.x
            dy = dst.y - src.y
            dist = max(math.hypot(dx, dy), 1.0)
            force = (dist * dist) / k
            fx = (dx / dist) * force
            fy = (dy / dist) * force
            if not src.pinned:
                src.vx += fx
                src.vy += fy
            if not dst.pinned:
                dst.vx -= fx
                dst.vy -= fy

        # Apply velocities with temperature limiting
        margin = 40
        for node in nodes:
            if node.pinned:
                continue
            speed = max(math.hypot(node.vx, node.vy), 0.01)
            node.x += (node.vx / speed) * min(speed, temp)
            node.y += (node.vy / speed) * min(speed, temp)
            node.x = max(margin, min(w - margin, node.x))
            node.y = max(margin, min(h - margin, node.y))
            node.vx *= 0.8  # damping
            node.vy *= 0.8

        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Background
        painter.fillRect(0, 0, w, h, QColor("#11111b"))

        # Subtle radial grid
        center = QPointF(w / 2, h / 2)
        painter.setPen(QPen(QColor(255, 255, 255, 8), 0.5))
        for r in range(50, max(w, h), 80):
            painter.drawEllipse(center, r, r)

        # Draw edges
        for edge in self._edges:
            src = self._nodes.get(edge.src_id)
            dst = self._nodes.get(edge.dst_id)
            if not src or not dst:
                continue

            alpha = min(120, int(40 + edge.weight * 0.01))
            thickness = max(1, min(4, 1 + edge.weight * 0.001))
            color = QColor(69, 71, 90, alpha)
            painter.setPen(QPen(color, thickness))
            painter.drawLine(QPointF(src.x, src.y), QPointF(dst.x, dst.y))

        # Draw nodes
        for node in self._nodes.values():
            cfg = node.config
            size = cfg["size"]
            base_color = QColor(cfg["color"])

            if not node.is_online:
                base_color = QColor("#f38ba8")  # red for offline
                base_color.setAlpha(120)

            pt = QPointF(node.x, node.y)

            # Glow effect
            glow = QRadialGradient(pt, size * 1.5)
            glow.setColorAt(0, QColor(base_color.red(), base_color.green(), base_color.blue(), 40))
            glow.setColorAt(1, QColor(0, 0, 0, 0))
            painter.setBrush(QBrush(glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(pt, size * 1.5, size * 1.5)

            # Node circle
            node_gradient = QRadialGradient(pt, size)
            node_gradient.setColorAt(0, base_color.lighter(130))
            node_gradient.setColorAt(1, base_color.darker(130))
            painter.setBrush(QBrush(node_gradient))
            border_color = base_color.lighter(160)
            painter.setPen(QPen(border_color, 1.5))
            painter.drawEllipse(pt, size, size)

            # Icon letter
            font = QFont("Consolas", int(size * 0.55), QFont.Bold)
            painter.setFont(font)
            painter.setPen(QColor("#1e1e2e"))
            painter.drawText(
                QRectF(pt.x() - size, pt.y() - size, size * 2, size * 2),
                Qt.AlignCenter, cfg["icon"],
            )

            # Label below node
            font = QFont("Segoe UI", 8)
            painter.setFont(font)
            painter.setPen(QColor("#a6adc8"))
            label = node.label if len(node.label) < 20 else node.label[:17] + "..."
            painter.drawText(
                QRectF(pt.x() - 60, pt.y() + size + 2, 120, 16),
                Qt.AlignCenter, label,
            )

        # Title
        painter.setPen(QColor("#cdd6f4"))
        font = QFont("Segoe UI", 11, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(10, 6, w, 24), Qt.AlignLeft | Qt.AlignTop, "Network Topology")

        # Legend
        x_leg = w - 180
        y_leg = h - 20
        font = QFont("Consolas", 8)
        painter.setFont(font)
        for i, (dtype, cfg) in enumerate(DEVICE_TYPES.items()):
            if i > 3:
                break
            x = x_leg + i * 45
            painter.setBrush(QBrush(QColor(cfg["color"])))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(x, y_leg), 4, 4)
            painter.setPen(QColor("#a6adc8"))
            painter.drawText(QPointF(x + 6, y_leg + 4), cfg["icon"])

        painter.end()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.position() if hasattr(event, 'position') else event.pos()
            for node in self._nodes.values():
                if math.hypot(node.x - pos.x(), node.y - pos.y()) < node.config["size"]:
                    self._dragging_node = node
                    node.pinned = True
                    self._drag_offset = QPointF(node.x - pos.x(), node.y - pos.y())
                    break

    def mouseMoveEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.pos()
        if self._dragging_node:
            self._dragging_node.x = pos.x() + self._drag_offset.x()
            self._dragging_node.y = pos.y() + self._drag_offset.y()
            self.update()
        else:
            # Hover tooltip
            for node in self._nodes.values():
                if math.hypot(node.x - pos.x(), node.y - pos.y()) < node.config["size"]:
                    dev = node.data
                    tip = (f"IP: {dev.get('ip', '')}\n"
                           f"MAC: {dev.get('mac', '')}\n"
                           f"Host: {dev.get('hostname', '')}\n"
                           f"OS: {dev.get('os_info', '')}\n"
                           f"Vendor: {dev.get('vendor', '')}\n"
                           f"Status: {'Online' if node.is_online else 'Offline'}")
                    gp = event.globalPosition().toPoint() if hasattr(event, 'globalPosition') else event.globalPos()
                    QToolTip.showText(gp, tip)
                    return
            QToolTip.hideText()

    def mouseReleaseEvent(self, event):
        if self._dragging_node:
            self._dragging_node.pinned = False
            self._dragging_node = None
