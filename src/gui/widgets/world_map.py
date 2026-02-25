"""Interactive world map using QWebEngineView + Leaflet.js with real map tiles."""

from PySide6.QtCore import QUrl, Signal
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWidgets import QVBoxLayout, QWidget


LEAFLET_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body, #map { width: 100%; height: 100%; background: #11111b; }
  .leaflet-control-attribution { display: none !important; }
  .leaflet-control-zoom a {
    background-color: #313244 !important;
    color: #cdd6f4 !important;
    border-color: #45475a !important;
  }
  .leaflet-control-zoom a:hover { background-color: #45475a !important; }

  /* Pulsing local marker */
  @keyframes pulse-ring {
    0%   { transform: scale(0.6); opacity: 1; }
    100% { transform: scale(2.5); opacity: 0; }
  }
  .pulse-marker {
    width: 14px; height: 14px;
    background: #89b4fa;
    border-radius: 50%;
    box-shadow: 0 0 12px #89b4fa;
    position: relative;
  }
  .pulse-marker::after {
    content: '';
    position: absolute;
    top: -4px; left: -4px;
    width: 22px; height: 22px;
    border: 3px solid #89b4fa;
    border-radius: 50%;
    animation: pulse-ring 1.5s ease-out infinite;
  }

  /* Info overlay */
  #info-overlay {
    position: absolute;
    top: 10px; left: 60px;
    z-index: 1000;
    background: rgba(30,30,46,0.9);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 10px 16px;
    color: #cdd6f4;
    font-family: "Consolas", monospace;
    font-size: 12px;
    pointer-events: none;
  }
  #info-overlay .title {
    font-size: 14px;
    font-weight: bold;
    color: #89b4fa;
    margin-bottom: 4px;
  }
  #info-overlay .stat {
    color: #a6adc8;
  }
  #info-overlay .stat b { color: #cdd6f4; }

  /* Legend */
  #legend {
    position: absolute;
    bottom: 10px; left: 10px;
    z-index: 1000;
    background: rgba(30,30,46,0.9);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 8px 12px;
    color: #a6adc8;
    font-family: "Consolas", monospace;
    font-size: 11px;
    pointer-events: none;
  }
  .legend-item { display: flex; align-items: center; gap: 6px; margin: 2px 0; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; }

  /* Custom popup */
  .leaflet-popup-content-wrapper {
    background: #1e1e2e !important;
    border: 1px solid #45475a !important;
    border-radius: 8px !important;
    color: #cdd6f4 !important;
    font-family: "Consolas", monospace !important;
  }
  .leaflet-popup-tip { background: #1e1e2e !important; }
  .popup-title { font-weight: bold; color: #89b4fa; font-size: 13px; margin-bottom: 4px; }
  .popup-row { color: #a6adc8; font-size: 11px; }
  .popup-row b { color: #cdd6f4; }
</style>
</head>
<body>
<div id="map"></div>
<div id="info-overlay">
  <div class="title">GLOBAL CONNECTIONS</div>
  <div class="stat">Endpoints: <b id="stat-endpoints">0</b></div>
  <div class="stat">Connections: <b id="stat-connections">0</b></div>
  <div class="stat">Countries: <b id="stat-countries">0</b></div>
</div>
<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#89b4fa;box-shadow:0 0 6px #89b4fa;"></div> Local Position</div>
  <div class="legend-item"><div class="legend-dot" style="background:#a6e3a1;"></div> Low (1-3)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f9e2af;"></div> Medium (4-10)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f38ba8;"></div> High (11+)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#cba6f7;"></div> Threat Flagged</div>
</div>

<script>
var map = L.map('map', {
    center: [30, 0],
    zoom: 2,
    minZoom: 2,
    maxZoom: 15,
    zoomControl: true,
    preferCanvas: true
});

// Dark tile layer - CartoDB Dark Matter
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19
}).addTo(map);

var localMarker = null;
var connectionMarkers = [];
var connectionLines = [];
var threatCircles = [];

function getColor(count, threat) {
    if (threat) return '#cba6f7';
    if (count <= 3) return '#a6e3a1';
    if (count <= 10) return '#f9e2af';
    return '#f38ba8';
}

function setLocalPosition(lat, lon) {
    if (localMarker) map.removeLayer(localMarker);

    var icon = L.divIcon({
        className: '',
        html: '<div class="pulse-marker"></div>',
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });
    localMarker = L.marker([lat, lon], { icon: icon, zIndexOffset: 1000 })
        .addTo(map)
        .bindPopup('<div class="popup-title">LOCAL POSITION</div>' +
                   '<div class="popup-row">Lat: <b>' + lat.toFixed(4) + '</b></div>' +
                   '<div class="popup-row">Lon: <b>' + lon.toFixed(4) + '</b></div>');
}

function clearConnections() {
    connectionMarkers.forEach(function(m) { map.removeLayer(m); });
    connectionLines.forEach(function(l) { map.removeLayer(l); });
    threatCircles.forEach(function(c) { map.removeLayer(c); });
    connectionMarkers = [];
    connectionLines = [];
    threatCircles = [];
}

function setConnections(connsJSON) {
    clearConnections();
    var conns = JSON.parse(connsJSON);

    var totalConns = 0;
    var countries = new Set();

    conns.forEach(function(c) {
        var lat = c.lat || 0;
        var lon = c.lon || 0;
        var count = c.count || 1;
        var country = c.country || 'Unknown';
        var city = c.city || '';
        var isp = c.isp || '';
        var threat = c.threat || false;

        totalConns += count;
        if (country) countries.add(country);

        var color = getColor(count, threat);
        var radius = Math.max(4, Math.min(14, 4 + Math.log2(count) * 3));

        // Endpoint circle marker
        var circle = L.circleMarker([lat, lon], {
            radius: radius,
            fillColor: color,
            fillOpacity: 0.8,
            color: color,
            weight: 1,
            opacity: 0.6
        }).addTo(map);

        // Popup
        var popupHtml = '<div class="popup-title">' + city + (city && country ? ', ' : '') + country + '</div>' +
                        '<div class="popup-row">Connections: <b>' + count + '</b></div>' +
                        '<div class="popup-row">ISP: <b>' + (isp || 'N/A') + '</b></div>' +
                        '<div class="popup-row">Coords: <b>' + lat.toFixed(2) + ', ' + lon.toFixed(2) + '</b></div>';
        if (threat) {
            popupHtml += '<div class="popup-row" style="color:#f38ba8;font-weight:bold;">THREAT FLAGGED</div>';
        }
        circle.bindPopup(popupHtml);
        connectionMarkers.push(circle);

        // Threat glow ring
        if (threat) {
            var glow = L.circleMarker([lat, lon], {
                radius: radius + 8,
                fillColor: '#f38ba8',
                fillOpacity: 0.15,
                color: '#f38ba8',
                weight: 2,
                opacity: 0.4,
                dashArray: '4 4'
            }).addTo(map);
            threatCircles.push(glow);
        }

        // Arc line from local to endpoint
        if (localMarker) {
            var localLatLng = localMarker.getLatLng();
            var midLat = (localLatLng.lat + lat) / 2;
            var midLon = (localLatLng.lng + lon) / 2;
            // Create curved path using intermediate points
            var dist = Math.sqrt(Math.pow(lat - localLatLng.lat, 2) + Math.pow(lon - localLatLng.lng, 2));
            var offset = dist * 0.15;
            var points = [];
            var steps = 30;
            for (var i = 0; i <= steps; i++) {
                var t = i / steps;
                var cLat = (1-t)*(1-t)*localLatLng.lat + 2*(1-t)*t*(midLat + offset) + t*t*lat;
                var cLon = (1-t)*(1-t)*localLatLng.lng + 2*(1-t)*t*midLon + t*t*lon;
                points.push([cLat, cLon]);
            }

            var lineAlpha = Math.min(0.7, 0.15 + count * 0.05);
            var lineWeight = Math.max(1, Math.min(4, 0.8 + count * 0.3));

            var line = L.polyline(points, {
                color: color,
                weight: lineWeight,
                opacity: lineAlpha,
                smoothFactor: 1,
                dashArray: threat ? '6 4' : null
            }).addTo(map);
            connectionLines.push(line);
        }
    });

    // Update overlay stats
    document.getElementById('stat-endpoints').textContent = conns.length;
    document.getElementById('stat-connections').textContent = totalConns;
    document.getElementById('stat-countries').textContent = countries.size;
}

// Initialize with default local position
setLocalPosition(37.8, -122.4);
</script>
</body>
</html>"""


class WorldMapWidget(QWidget):
    """Interactive world map using Leaflet.js via QWebEngineView."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(500, 280)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._web = QWebEngineView()
        self._web.setHtml(LEAFLET_HTML, QUrl("about:blank"))
        layout.addWidget(self._web)

        self._connections: list[dict] = []
        self._local_lat = 37.8
        self._local_lon = -122.4
        self._page_loaded = False

        self._web.loadFinished.connect(self._on_load)

    def _on_load(self, ok: bool):
        if ok:
            self._page_loaded = True
            self._push_local()
            if self._connections:
                self._push_connections()

    def _run_js(self, js: str):
        if self._page_loaded:
            self._web.page().runJavaScript(js)

    def set_local_position(self, lat: float, lon: float):
        self._local_lat = lat
        self._local_lon = lon
        self._push_local()

    def _push_local(self):
        self._run_js(f"setLocalPosition({self._local_lat}, {self._local_lon});")

    def set_connections(self, connections: list[dict]):
        self._connections = connections
        self._push_connections()

    def _push_connections(self):
        import json
        data = json.dumps(self._connections)
        escaped = data.replace("\\", "\\\\").replace("'", "\\'")
        self._run_js(f"setConnections('{escaped}');")
