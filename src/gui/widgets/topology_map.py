"""Interactive network topology map with animated traffic flow."""

import math

from PySide6.QtCore import (
    QPointF,
    QRectF,
    QTimeLine,
    Qt,
)
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QToolTip,
)

from src.gui import theme

_NODE_RADIUS = 14
_MAX_TRAFFIC_DOTS = 20


class DeviceNode(QGraphicsEllipseItem):
    """A single device node on the topology map."""

    def __init__(self, ip: str, data: dict, x: float, y: float, parent=None):
        d = _NODE_RADIUS * 2
        super().__init__(-_NODE_RADIUS, -_NODE_RADIUS, d, d, parent)
        self.setPos(x, y)
        self.setAcceptHoverEvents(True)
        self._ip = ip
        self._data = data
        self._is_gateway = False

        # Label below node
        self._label = QGraphicsSimpleTextItem(self)
        self._label.setFont(QFont("Courier New", 7))
        self._label.setBrush(QColor(theme.GREEN_DIM))
        label_text = data.get("hostname") or ip
        if len(label_text) > 15:
            label_text = label_text[:13] + ".."
        self._label.setText(label_text)
        tw = self._label.boundingRect().width()
        self._label.setPos(-tw / 2, _NODE_RADIUS + 2)

        self.update_status(data)

    def mark_gateway(self):
        self._is_gateway = True
        self.setRect(-_NODE_RADIUS * 1.3, -_NODE_RADIUS * 1.3,
                     _NODE_RADIUS * 2.6, _NODE_RADIUS * 2.6)
        self.setBrush(QColor(theme.CYAN))
        pen = QPen(QColor(theme.GREEN), 2)
        self.setPen(pen)
        self._label.setText("GATEWAY")
        tw = self._label.boundingRect().width()
        self._label.setPos(-tw / 2, _NODE_RADIUS * 1.3 + 2)

    def update_status(self, data: dict, is_trusted: bool = True):
        self._data = data
        is_online = data.get("is_online", False)
        if self._is_gateway:
            return
        if not is_online:
            self.setBrush(QColor(theme.GREEN_DARK))
            self.setPen(QPen(QColor(theme.BORDER), 1))
        elif not is_trusted:
            self.setBrush(QColor(theme.AMBER))
            self.setPen(QPen(QColor("#cc8800"), 1.5))
        else:
            self.setBrush(QColor(theme.GREEN))
            self.setPen(QPen(QColor(theme.GREEN_DIM), 1))

    def hoverEnterEvent(self, event):
        info = self._data
        tip = (
            f"IP: {info.get('ip', '?')}\n"
            f"MAC: {info.get('mac', '?')}\n"
            f"Host: {info.get('hostname', '?')}\n"
            f"Vendor: {info.get('vendor', '?')}\n"
            f"Status: {'Online' if info.get('is_online') else 'Offline'}\n"
            f"Last seen: {info.get('last_seen', '?')}"
        )
        QToolTip.showText(event.screenPos().toPoint(), tip)

    def hoverLeaveEvent(self, event):
        QToolTip.hideText()


class TrafficDot(QGraphicsEllipseItem):
    """Small animated dot that moves along a path."""

    def __init__(self, parent=None):
        super().__init__(-2, -2, 4, 4, parent)
        self.setBrush(QColor(theme.GREEN))
        self.setPen(Qt.NoPen)
        self.setZValue(10)


class TopologyMapWidget(QGraphicsView):
    """Network topology map with radial device layout and traffic animation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setStyleSheet(
            f"QGraphicsView {{ background-color: {theme.BG_DARKEST}; "
            f"border: 1px solid {theme.BORDER}; }}"
        )
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self._gateway_node: DeviceNode | None = None
        self._device_nodes: dict[str, DeviceNode] = {}
        self._traffic_lines: list[QGraphicsPathItem] = []
        self._dot_pool: list[tuple[TrafficDot, QTimeLine]] = []

    def drawBackground(self, painter: QPainter, rect: QRectF):
        """Draw a military radar-style grid background."""
        painter.fillRect(rect, QColor(theme.BG_DARKEST))
        pen = QPen(QColor(theme.GRID_LINE), 0.5)
        painter.setPen(pen)

        # Grid lines
        step = 50
        left = int(rect.left()) - (int(rect.left()) % step) - step
        top = int(rect.top()) - (int(rect.top()) % step) - step
        for x in range(left, int(rect.right()) + step, step):
            painter.drawLine(x, int(rect.top()), x, int(rect.bottom()))
        for y in range(top, int(rect.bottom()) + step, step):
            painter.drawLine(int(rect.left()), y, int(rect.right()), y)

        # Concentric circles from origin
        circle_pen = QPen(QColor(theme.GRID_LINE), 0.5, Qt.DashLine)
        painter.setPen(circle_pen)
        for r in (80, 160, 240):
            painter.drawEllipse(QPointF(0, 0), r, r)

    def update_devices(self, devices: list[dict], gateway_ip: str,
                       trusted_macs: set[str] | None = None):
        """Rebuild the topology from the device list."""
        # Clear old items
        for item in self._traffic_lines:
            self._scene.removeItem(item)
        self._traffic_lines.clear()
        self._stop_dots()

        trusted = trusted_macs or set()
        current_ips = set()

        # Ensure gateway node exists
        if gateway_ip and gateway_ip not in self._device_nodes:
            gw_data = {"ip": gateway_ip, "hostname": "Gateway", "is_online": True,
                       "mac": "", "vendor": "", "last_seen": ""}
            for d in devices:
                if d.get("ip") == gateway_ip:
                    gw_data = d
                    break
            node = DeviceNode(gateway_ip, gw_data, 0, 0)
            node.mark_gateway()
            self._scene.addItem(node)
            self._device_nodes[gateway_ip] = node
            self._gateway_node = node
        elif gateway_ip and gateway_ip in self._device_nodes:
            self._gateway_node = self._device_nodes[gateway_ip]

        # Layout non-gateway devices in a circle
        other_devices = [d for d in devices if d.get("ip") != gateway_ip]
        n = len(other_devices)
        radius = 150 if n <= 12 else 120

        for i, dev in enumerate(other_devices):
            ip = dev.get("ip", "")
            if not ip:
                continue
            current_ips.add(ip)
            angle = (2 * math.pi * i / max(n, 1)) - math.pi / 2

            # Two rings if >12 devices
            r = radius if i < 12 else radius + 80
            x = r * math.cos(angle)
            y = r * math.sin(angle)

            is_trusted = dev.get("mac", "") in trusted

            if ip in self._device_nodes:
                node = self._device_nodes[ip]
                node.setPos(x, y)
                node.update_status(dev, is_trusted)
            else:
                node = DeviceNode(ip, dev, x, y)
                node.update_status(dev, is_trusted)
                self._scene.addItem(node)
                self._device_nodes[ip] = node

        # Remove stale nodes (except gateway)
        stale = [ip for ip in self._device_nodes
                 if ip != gateway_ip and ip not in current_ips]
        for ip in stale:
            self._scene.removeItem(self._device_nodes.pop(ip))

        # Draw traffic lines from each device to gateway
        if self._gateway_node:
            gw_pos = self._gateway_node.pos()
            for ip, node in self._device_nodes.items():
                if ip == gateway_ip:
                    continue
                dev_pos = node.pos()
                # Bezier control point offset perpendicular to midpoint
                mid = (gw_pos + dev_pos) / 2
                dx = dev_pos.x() - gw_pos.x()
                dy = dev_pos.y() - gw_pos.y()
                dist = math.sqrt(dx * dx + dy * dy)
                if dist > 0:
                    perp_x = -dy / dist * 20
                    perp_y = dx / dist * 20
                else:
                    perp_x, perp_y = 0, 20
                ctrl = QPointF(mid.x() + perp_x, mid.y() + perp_y)

                path = QPainterPath()
                path.moveTo(gw_pos)
                path.quadTo(ctrl, dev_pos)

                line_item = QGraphicsPathItem(path)
                pen = QPen(QColor(theme.GREEN_DARK), 1, Qt.DashLine)
                line_item.setPen(pen)
                line_item.setZValue(-1)
                self._scene.addItem(line_item)
                self._traffic_lines.append(line_item)

                # Animate traffic dot along path
                if len(self._dot_pool) < _MAX_TRAFFIC_DOTS:
                    self._add_traffic_dot(path)

        # Fit view
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))
        self.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)

    def _add_traffic_dot(self, path: QPainterPath):
        dot = TrafficDot()
        self._scene.addItem(dot)

        timeline = QTimeLine(3000)
        timeline.setFrameRange(0, 100)
        timeline.setLoopCount(0)  # infinite

        def move_dot(frame):
            pct = frame / 100.0
            pt = path.pointAtPercent(pct)
            dot.setPos(pt)

        timeline.frameChanged.connect(move_dot)
        timeline.start()
        self._dot_pool.append((dot, timeline))

    def _stop_dots(self):
        for dot, tl in self._dot_pool:
            tl.stop()
            self._scene.removeItem(dot)
        self._dot_pool.clear()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._scene.items():
            self.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)
