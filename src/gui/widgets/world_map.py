"""Geo-IP world map widget with animated connection arcs."""

import math

from PySide6.QtCore import QPointF, QPropertyAnimation, QEasingCurve, QTimer, Property, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from src.gui import theme


# ── Simplified continent outlines (lat, lon pairs) ──────────────────────────

_NORTH_AMERICA = [
    (49, -125), (60, -140), (70, -160), (72, -155), (71, -138),
    (69, -105), (62, -75), (52, -55), (47, -53), (45, -66),
    (30, -82), (25, -80), (25, -97), (20, -105), (15, -92),
    (15, -84), (10, -84), (8, -77), (18, -88), (21, -87),
    (30, -115), (32, -117), (38, -123), (48, -124), (49, -125),
]

_SOUTH_AMERICA = [
    (12, -72), (10, -62), (7, -60), (5, -51), (0, -50),
    (-5, -35), (-15, -39), (-23, -41), (-33, -52), (-42, -63),
    (-55, -69), (-55, -66), (-47, -73), (-40, -73), (-30, -72),
    (-18, -70), (-5, -80), (2, -78), (10, -75), (12, -72),
]

_EUROPE = [
    (36, -10), (38, -5), (43, -8), (48, -5), (51, 2),
    (54, 8), (57, 10), (63, 5), (71, 25), (70, 30),
    (60, 30), (55, 28), (50, 30), (47, 40), (42, 28),
    (38, 24), (36, 28), (35, 24), (38, 15), (38, 12),
    (41, 12), (43, 10), (44, 8), (43, 3), (37, -2),
    (36, -5), (36, -10),
]

_AFRICA = [
    (37, -1), (37, 10), (32, 12), (30, 32), (22, 36),
    (12, 44), (2, 42), (-12, 40), (-26, 33), (-34, 18),
    (-34, 25), (-30, 30), (-15, 35), (-8, 40), (0, 42),
    (-34, 18), (-33, 17), (-28, 15), (-22, 14), (-17, 12),
    (-5, 12), (5, 1), (5, -5), (10, -15), (15, -17),
    (20, -17), (28, -13), (35, -1), (37, -1),
]

_ASIA = [
    (42, 28), (45, 40), (42, 52), (37, 55), (25, 56),
    (12, 44), (8, 77), (23, 70), (22, 88), (20, 92),
    (28, 97), (22, 100), (10, 106), (1, 104), (-8, 110),
    (-8, 115), (0, 118), (5, 120), (20, 110), (22, 114),
    (32, 121), (40, 122), (45, 131), (52, 141), (55, 135),
    (62, 135), (65, 140), (68, 170), (66, 175), (64, 177),
    (70, 180), (72, 155), (72, 130), (73, 80), (70, 55),
    (55, 28), (50, 30), (47, 40), (42, 28),
]

_AUSTRALIA = [
    (-12, 130), (-15, 124), (-22, 114), (-32, 115), (-35, 117),
    (-35, 138), (-38, 145), (-38, 148), (-33, 152), (-28, 153),
    (-23, 150), (-18, 146), (-16, 146), (-12, 142), (-10, 142),
    (-12, 137), (-12, 130),
]

_CONTINENTS = [
    _NORTH_AMERICA, _SOUTH_AMERICA, _EUROPE, _AFRICA, _ASIA, _AUSTRALIA,
]

# ── Country centroid lookup (lat, lon) ───────────────────────────────────────

COUNTRY_CENTROIDS = {
    "US": (39.8, -98.5), "CA": (56.1, -106.3), "MX": (23.6, -102.5),
    "BR": (-14.2, -51.9), "AR": (-38.4, -63.6), "CO": (4.6, -74.3),
    "GB": (55.4, -3.4), "DE": (51.2, 10.4), "FR": (46.2, 2.2),
    "ES": (40.5, -3.7), "IT": (41.9, 12.6), "NL": (52.1, 5.3),
    "SE": (60.1, 18.6), "NO": (60.5, 8.5), "PL": (51.9, 19.1),
    "RU": (61.5, 105.3), "UA": (48.4, 31.2), "TR": (39.0, 35.2),
    "CN": (35.9, 104.2), "JP": (36.2, 138.3), "KR": (35.9, 127.8),
    "IN": (20.6, 79.0), "ID": (-0.8, 114.0), "TH": (15.9, 101.0),
    "VN": (14.1, 108.3), "PH": (12.9, 121.8), "SG": (1.4, 103.8),
    "AU": (-25.3, 133.8), "NZ": (-40.9, 174.9),
    "ZA": (-30.6, 22.9), "EG": (26.8, 30.8), "NG": (9.1, 8.7),
    "KE": (-0.0, 37.9), "IL": (31.0, 34.9), "SA": (23.9, 45.1),
    "AE": (23.4, 53.8), "IR": (32.4, 53.7), "PK": (30.4, 69.3),
    "BD": (23.7, 90.4), "TW": (23.7, 121.0), "HK": (22.4, 114.1),
    "IE": (53.4, -8.2), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "BE": (50.5, 4.5), "FI": (61.9, 25.7), "DK": (56.3, 9.5),
    "CZ": (49.8, 15.5), "RO": (45.9, 25.0), "CL": (-35.7, -71.5),
    "PE": (-9.2, -75.0), "VE": (6.4, -66.6),
}


class WorldMapWidget(QWidget):
    """Simplified world map with animated connection arcs."""

    def __init__(self, local_coords: tuple = (39.8, -98.5), parent=None):
        super().__init__(parent)
        self._local_coords = local_coords
        self._connections: list[dict] = []
        self._continent_paths: list[QPainterPath] = []
        self._arc_progress: dict[str, float] = {}
        self._arc_anims: dict[str, QPropertyAnimation] = {}
        self._pulse_phase = 0.0
        self.setMinimumHeight(150)

        # Pulse timer for endpoint dots
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(50)
        self._pulse_timer.timeout.connect(self._pulse_tick)
        self._pulse_timer.start()

    def _pulse_tick(self):
        self._pulse_phase += 0.08
        if self._pulse_phase > 2 * math.pi:
            self._pulse_phase -= 2 * math.pi
        if self._connections:
            self.update()

    def _geo_to_screen(self, lat: float, lon: float) -> QPointF:
        """Mercator projection: lat/lon to widget pixel coordinates."""
        w = self.width()
        h = self.height()
        x = (lon + 180) / 360 * w
        lat_rad = math.radians(max(-80, min(80, lat)))
        merc_y = math.log(math.tan(math.pi / 4 + lat_rad / 2))
        y = h / 2 - (merc_y / (2 * math.pi)) * w * 0.6
        return QPointF(x, y)

    def _build_continent_paths(self):
        """Build QPainterPaths from continent coordinate lists."""
        self._continent_paths.clear()
        for coords in _CONTINENTS:
            path = QPainterPath()
            for i, (lat, lon) in enumerate(coords):
                pt = self._geo_to_screen(lat, lon)
                if i == 0:
                    path.moveTo(pt)
                else:
                    path.lineTo(pt)
            path.closeSubpath()
            self._continent_paths.append(path)

    def update_connections(self, connections: list[dict]):
        """Update connection data: [{country_code, country_name, threat, count}]."""
        self._connections = connections
        # Animate new countries
        for conn in connections:
            cc = conn.get("country_code", "")
            if cc and cc not in self._arc_progress:
                self._arc_progress[cc] = 0.0
                self._animate_arc(cc)
        self.update()

    def _animate_arc(self, country_code: str):
        """Animate arc draw from 0 to 1."""
        # Use a helper QObject to hold the property
        class _Holder:
            pass
        # Direct approach: just set to 1.0 over time via timer
        # Since we can't easily use QPropertyAnimation on a dict value,
        # we'll use a QTimer approach
        self._arc_progress[country_code] = 0.0
        steps = [0]

        def step():
            steps[0] += 1
            progress = min(1.0, steps[0] / 20.0)
            self._arc_progress[country_code] = progress
            self.update()
            if progress >= 1.0:
                timer.stop()

        timer = QTimer(self)
        timer.setInterval(40)
        timer.timeout.connect(step)
        timer.start()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._build_continent_paths()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Background
        painter.fillRect(0, 0, w, h, QColor(theme.BG_DARKEST))

        # Draw continents
        if not self._continent_paths:
            self._build_continent_paths()

        continent_fill = QColor(theme.BG_ELEVATED)
        continent_pen = QPen(QColor(theme.GREEN_DARK), 1)
        for path in self._continent_paths:
            painter.setPen(continent_pen)
            painter.setBrush(continent_fill)
            painter.drawPath(path)

        # Local position marker
        local_pt = self._geo_to_screen(*self._local_coords)
        pulse_r = 4 + 2 * math.sin(self._pulse_phase)

        # Crosshair
        ch_pen = QPen(QColor(theme.GREEN), 1)
        painter.setPen(ch_pen)
        painter.drawLine(
            int(local_pt.x() - 8), int(local_pt.y()),
            int(local_pt.x() + 8), int(local_pt.y())
        )
        painter.drawLine(
            int(local_pt.x()), int(local_pt.y() - 8),
            int(local_pt.x()), int(local_pt.y() + 8)
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(theme.GREEN))
        painter.drawEllipse(local_pt, pulse_r, pulse_r)

        # Draw connection arcs
        for conn in self._connections:
            cc = conn.get("country_code", "")
            centroid = COUNTRY_CENTROIDS.get(cc)
            if not centroid:
                continue

            dest_pt = self._geo_to_screen(*centroid)
            progress = self._arc_progress.get(cc, 1.0)
            threat = conn.get("threat", "safe")
            count = conn.get("count", 1)

            # Arc color
            if threat == "critical":
                arc_color = QColor(theme.RED)
            elif threat == "warning":
                arc_color = QColor(theme.AMBER)
            else:
                arc_color = QColor(theme.GREEN)

            # Bezier control point — raised above midpoint
            mid_x = (local_pt.x() + dest_pt.x()) / 2
            mid_y = (local_pt.y() + dest_pt.y()) / 2
            dx = dest_pt.x() - local_pt.x()
            dy = dest_pt.y() - local_pt.y()
            dist = math.sqrt(dx * dx + dy * dy)
            lift = min(dist * 0.3, 80)
            ctrl_pt = QPointF(mid_x, mid_y - lift)

            # Build arc path
            arc_path = QPainterPath()
            arc_path.moveTo(local_pt)
            arc_path.quadTo(ctrl_pt, dest_pt)

            # Draw partial arc based on progress
            if progress < 1.0:
                # Draw portion of the arc
                partial = QPainterPath()
                steps = max(2, int(50 * progress))
                for s in range(steps + 1):
                    t = s / 50
                    if t > progress:
                        break
                    pt = arc_path.pointAtPercent(min(t, 1.0))
                    if s == 0:
                        partial.moveTo(pt)
                    else:
                        partial.lineTo(pt)
                pen = QPen(arc_color, 1.5)
                painter.setPen(pen)
                painter.setBrush(Qt.NoBrush)
                painter.drawPath(partial)
            else:
                pen = QPen(arc_color, 1.5)
                painter.setPen(pen)
                painter.setBrush(Qt.NoBrush)
                painter.drawPath(arc_path)

            # Endpoint dot (pulsing)
            dot_r = 3 + 1.5 * math.sin(self._pulse_phase + hash(cc) % 10)
            painter.setPen(Qt.NoPen)
            dot_color = QColor(arc_color)
            dot_color.setAlpha(200)
            painter.setBrush(dot_color)
            painter.drawEllipse(dest_pt, dot_r, dot_r)

            # Country label
            label_font = QFont("Courier New", 7, QFont.Bold)
            painter.setFont(label_font)
            painter.setPen(arc_color)
            painter.drawText(int(dest_pt.x() + 6), int(dest_pt.y() - 4), cc)

        # Title
        painter.setPen(QColor(theme.GREEN))
        painter.setFont(QFont("Courier New", 9, QFont.Bold))
        painter.drawText(6, 14, "GLOBAL CONNECTIONS")

        # Connection count
        if self._connections:
            total = sum(c.get("count", 0) for c in self._connections)
            countries = len(self._connections)
            painter.setFont(QFont("Courier New", 7))
            painter.setPen(QColor(theme.GREEN_MUTED))
            painter.drawText(6, h - 6,
                             f"{countries} countries | {total} connections")

        painter.end()

    def set_local_coords(self, lat: float, lon: float):
        self._local_coords = (lat, lon)
        self.update()
