"""Professional world map widget with animated connection arcs using QPainter."""

import math
from PySide6.QtCore import Qt, QRectF, QPointF, QTimer
from PySide6.QtGui import (
    QPainter, QColor, QPen, QBrush, QPainterPath, QFont,
    QRadialGradient, QLinearGradient, QPolygonF,
)
from PySide6.QtWidgets import QWidget, QToolTip

from src.data.world_coordinates import ALL_LAND_POLYGONS


class WorldMapWidget(QWidget):
    """Renders a world map with animated connection arcs to GeoIP-resolved IPs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(500, 280)
        self._connections: list[dict] = []  # [{lat, lon, country, city, count, ...}]
        self._local_lat = 37.8  # default: San Francisco
        self._local_lon = -122.4
        self._pulse_phase = 0.0
        self._hover_point = None

        self.setMouseTracking(True)

        # Animation timer for pulsing connection dots
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(33)  # ~30fps
        self._pulse_timer.timeout.connect(self._pulse_tick)
        self._pulse_timer.start()

    def set_local_position(self, lat: float, lon: float):
        self._local_lat = lat
        self._local_lon = lon
        self.update()

    def set_connections(self, connections: list[dict]):
        """Set connection endpoints. Each dict: {lat, lon, country, city, count, isp}."""
        self._connections = connections
        self.update()

    def _pulse_tick(self):
        self._pulse_phase = (self._pulse_phase + 0.03) % 1.0
        if self._connections:
            self.update()

    def _lonlat_to_pixel(self, lon: float, lat: float) -> QPointF:
        """Mercator projection: lon/lat → pixel coordinates."""
        w = self.width()
        h = self.height()
        # Clamp latitude to avoid infinity in mercator
        lat = max(-80, min(80, lat))
        x = (lon + 180) / 360 * w
        lat_rad = math.radians(lat)
        merc_y = math.log(math.tan(math.pi / 4 + lat_rad / 2))
        y = h / 2 - (merc_y / math.pi) * (h / 2)
        return QPointF(x, y)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Ocean background
        painter.fillRect(0, 0, w, h, QColor("#11111b"))

        # Subtle grid lines
        painter.setPen(QPen(QColor(255, 255, 255, 12), 0.5))
        for lon in range(-180, 181, 30):
            p = self._lonlat_to_pixel(lon, 0)
            painter.drawLine(QPointF(p.x(), 0), QPointF(p.x(), h))
        for lat in range(-60, 61, 30):
            p = self._lonlat_to_pixel(0, lat)
            painter.drawLine(QPointF(0, p.y()), QPointF(w, p.y()))

        # Draw continents
        land_fill = QColor("#313244")
        land_outline = QColor("#45475a")
        painter.setBrush(QBrush(land_fill))
        painter.setPen(QPen(land_outline, 0.8))

        for polygon_coords in ALL_LAND_POLYGONS:
            poly = QPolygonF()
            for lon, lat in polygon_coords:
                pt = self._lonlat_to_pixel(lon, lat)
                poly.append(pt)
            if len(poly) >= 3:
                painter.drawPolygon(poly)

        # Draw connection arcs
        local_pt = self._lonlat_to_pixel(self._local_lon, self._local_lat)

        # Local position marker (pulsing glow)
        glow_radius = 6 + 3 * math.sin(self._pulse_phase * math.pi * 2)
        glow = QRadialGradient(local_pt, glow_radius * 2)
        glow.setColorAt(0, QColor(137, 180, 250, 180))
        glow.setColorAt(0.5, QColor(137, 180, 250, 60))
        glow.setColorAt(1, QColor(137, 180, 250, 0))
        painter.setBrush(QBrush(glow))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(local_pt, glow_radius * 2, glow_radius * 2)
        painter.setBrush(QBrush(QColor("#89b4fa")))
        painter.drawEllipse(local_pt, 4, 4)

        # Draw each connection
        for i, conn in enumerate(self._connections):
            dst_pt = self._lonlat_to_pixel(conn.get("lon", 0), conn.get("lat", 0))
            count = conn.get("count", 1)

            # Color by connection intensity: green (few) → yellow → red (many)
            if count <= 3:
                line_color = QColor("#a6e3a1")
                dot_color = QColor("#a6e3a1")
            elif count <= 10:
                line_color = QColor("#f9e2af")
                dot_color = QColor("#f9e2af")
            else:
                line_color = QColor("#f38ba8")
                dot_color = QColor("#f38ba8")

            # Draw bezier arc
            mid_x = (local_pt.x() + dst_pt.x()) / 2
            mid_y = (local_pt.y() + dst_pt.y()) / 2
            dist = math.hypot(dst_pt.x() - local_pt.x(), dst_pt.y() - local_pt.y())
            # Arc upward proportional to distance
            ctrl_y = mid_y - dist * 0.25
            ctrl_pt = QPointF(mid_x, ctrl_y)

            path = QPainterPath()
            path.moveTo(local_pt)
            path.quadTo(ctrl_pt, dst_pt)

            line_alpha = min(180, 60 + count * 10)
            line_color.setAlpha(line_alpha)
            pen_width = max(1, min(3, 0.5 + count * 0.3))
            painter.setPen(QPen(line_color, pen_width))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)

            # Animated pulse dot traveling along the arc
            phase = (self._pulse_phase + i * 0.13) % 1.0
            t = phase
            # Quadratic bezier: B(t) = (1-t)^2*P0 + 2(1-t)t*C + t^2*P1
            bx = (1 - t) ** 2 * local_pt.x() + 2 * (1 - t) * t * ctrl_pt.x() + t ** 2 * dst_pt.x()
            by = (1 - t) ** 2 * local_pt.y() + 2 * (1 - t) * t * ctrl_pt.y() + t ** 2 * dst_pt.y()
            pulse_pt = QPointF(bx, by)

            dot_color.setAlpha(200)
            painter.setBrush(QBrush(dot_color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(pulse_pt, 3, 3)

            # Destination marker (glowing dot)
            dst_glow = QRadialGradient(dst_pt, 8)
            dst_glow.setColorAt(0, QColor(dot_color.red(), dot_color.green(), dot_color.blue(), 160))
            dst_glow.setColorAt(1, QColor(dot_color.red(), dot_color.green(), dot_color.blue(), 0))
            painter.setBrush(QBrush(dst_glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(dst_pt, 8, 8)
            painter.setBrush(QBrush(QColor(dot_color.red(), dot_color.green(), dot_color.blue(), 220)))
            painter.drawEllipse(dst_pt, 3, 3)

            # Country label for top connections
            if count >= 3 or len(self._connections) <= 8:
                label = conn.get("city") or conn.get("country", "")
                if label:
                    painter.setPen(QColor(205, 214, 244, 180))
                    font = QFont("Segoe UI", 8)
                    painter.setFont(font)
                    painter.drawText(dst_pt + QPointF(6, -4), label)

        # Title overlay
        painter.setPen(QColor("#cdd6f4"))
        font = QFont("Segoe UI", 11, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(10, 6, w, 24), Qt.AlignLeft | Qt.AlignTop, "Global Connections")

        # Connection count legend
        if self._connections:
            total = sum(c.get("count", 1) for c in self._connections)
            countries = len(set(c.get("country", "") for c in self._connections))
            legend = f"{len(self._connections)} destinations  |  {total} connections  |  {countries} countries"
            font = QFont("Consolas", 8)
            painter.setFont(font)
            painter.setPen(QColor("#a6adc8"))
            painter.drawText(QRectF(10, h - 22, w - 20, 20), Qt.AlignLeft | Qt.AlignBottom, legend)

        painter.end()

    def mouseMoveEvent(self, event):
        # Show tooltip for nearby connection endpoints
        pos = event.position() if hasattr(event, 'position') else event.pos()
        for conn in self._connections:
            pt = self._lonlat_to_pixel(conn.get("lon", 0), conn.get("lat", 0))
            if math.hypot(pt.x() - pos.x(), pt.y() - pos.y()) < 15:
                city = conn.get("city", "Unknown")
                country = conn.get("country", "Unknown")
                isp = conn.get("isp", "")
                count = conn.get("count", 1)
                tip = f"{city}, {country}\n{isp}\nConnections: {count}"
                QToolTip.showText(event.globalPosition().toPoint() if hasattr(event, 'globalPosition') else event.globalPos(), tip)
                return
        QToolTip.hideText()
