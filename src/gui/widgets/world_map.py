"""Interactive 3D globe map using QWebEngineView + Three.js + globe.gl."""

from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QVBoxLayout, QWidget


GLOBE_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
<script src="https://unpkg.com/globe.gl@2.33.0/dist/globe.gl.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { width: 100%; height: 100%; background: #0a0a14; overflow: hidden; font-family: "Consolas", monospace; }
  #globe { width: 100%; height: 100%; }

  /* Info overlay */
  #info-overlay {
    position: absolute;
    top: 10px; left: 10px;
    z-index: 10;
    background: rgba(20,20,36,0.92);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 10px 16px;
    color: #cdd6f4;
    font-size: 12px;
    pointer-events: none;
  }
  #info-overlay .title {
    font-size: 14px;
    font-weight: bold;
    color: #89b4fa;
    margin-bottom: 4px;
  }
  #info-overlay .stat { color: #a6adc8; }
  #info-overlay .stat b { color: #cdd6f4; }

  /* Detail panel */
  #detail-panel {
    display: none;
    position: absolute;
    bottom: 10px; right: 10px;
    z-index: 10;
    background: rgba(20,20,36,0.95);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 12px 16px;
    color: #cdd6f4;
    font-size: 11px;
    min-width: 180px;
    max-width: 280px;
  }
  #detail-panel .detail-title {
    font-size: 13px;
    font-weight: bold;
    color: #89b4fa;
    margin-bottom: 6px;
  }
  #detail-panel .detail-row { color: #a6adc8; margin: 2px 0; }
  #detail-panel .detail-row b { color: #cdd6f4; }

  /* Legend */
  #legend {
    position: absolute;
    bottom: 10px; left: 10px;
    z-index: 10;
    background: rgba(20,20,36,0.92);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 8px 12px;
    color: #a6adc8;
    font-size: 11px;
    pointer-events: none;
  }
  .legend-item { display: flex; align-items: center; gap: 6px; margin: 2px 0; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; }

  /* Controls hint */
  #controls-hint {
    position: absolute;
    top: 10px; right: 10px;
    z-index: 10;
    background: rgba(20,20,36,0.8);
    border: 1px solid #313244;
    border-radius: 6px;
    padding: 6px 10px;
    color: #585b70;
    font-size: 10px;
    pointer-events: none;
    line-height: 1.5;
  }
</style>
</head>
<body>
<div id="globe"></div>
<div id="info-overlay">
  <div class="title">3D GLOBAL CONNECTIONS</div>
  <div class="stat">Endpoints: <b id="stat-endpoints">0</b></div>
  <div class="stat">Connections: <b id="stat-connections">0</b></div>
  <div class="stat">Countries: <b id="stat-countries">0</b></div>
</div>
<div id="detail-panel">
  <div class="detail-title" id="detail-title"></div>
  <div id="detail-content"></div>
</div>
<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#89b4fa;box-shadow:0 0 6px #89b4fa;"></div> Local Position</div>
  <div class="legend-item"><div class="legend-dot" style="background:#a6e3a1;"></div> Low (1-3)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f9e2af;"></div> Medium (4-10)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f38ba8;"></div> High (11+)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#cba6f7;"></div> Threat Flagged</div>
</div>
<div id="controls-hint">
  LMB drag: rotate &bull; Scroll: zoom<br/>
  Click point: details
</div>

<script>
// ── State ──────────────────────────────────────────
var localLat = 37.8, localLon = -122.4;
var connectionData = [];
var pointsData = [];
var arcsData = [];
var ringsData = [];

// ── Color helper ───────────────────────────────────
function getColor(count, threat) {
    if (threat) return '#cba6f7';
    if (count <= 3) return '#a6e3a1';
    if (count <= 10) return '#f9e2af';
    return '#f38ba8';
}

// ── Initialize Globe ───────────────────────────────
var globe = Globe()(document.getElementById('globe'))
    .globeImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-night.jpg')
    .bumpImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/earth-topology.png')
    .backgroundImageUrl('https://unpkg.com/three-globe@2.31.1/example/img/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor('#1a3a6a')
    .atmosphereAltitude(0.2)
    // Points layer (connection endpoints + local marker)
    .pointsData([])
    .pointLat('lat')
    .pointLng('lng')
    .pointAltitude(function(d) { return d.isLocal ? 0.02 : 0.01; })
    .pointRadius(function(d) {
        if (d.isLocal) return 0.4;
        return Math.max(0.15, Math.min(0.6, 0.15 + Math.log2(d.count || 1) * 0.12));
    })
    .pointColor(function(d) { return d.color; })
    .pointResolution(12)
    .onPointClick(function(point) {
        if (point.isLocal) return;
        var panel = document.getElementById('detail-panel');
        document.getElementById('detail-title').textContent =
            (point.city || '') + (point.city && point.country ? ', ' : '') + (point.country || 'Unknown');
        var html = '';
        html += '<div class="detail-row">Connections: <b>' + (point.count || 0) + '</b></div>';
        html += '<div class="detail-row">ISP: <b>' + (point.isp || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Coords: <b>' + point.lat.toFixed(2) + ', ' + point.lng.toFixed(2) + '</b></div>';
        if (point.threat) {
            html += '<div class="detail-row" style="color:#f38ba8;font-weight:bold;">THREAT FLAGGED</div>';
        }
        document.getElementById('detail-content').innerHTML = html;
        panel.style.display = 'block';

        // Focus globe on clicked point
        globe.pointOfView({ lat: point.lat, lng: point.lng, altitude: 1.5 }, 1000);
    })
    // Arcs layer (connections from local to endpoints)
    .arcsData([])
    .arcStartLat('startLat')
    .arcStartLng('startLng')
    .arcEndLat('endLat')
    .arcEndLng('endLng')
    .arcColor('color')
    .arcAltitude(function(d) {
        // Higher arcs for longer distances
        var dlat = d.endLat - d.startLat;
        var dlng = d.endLng - d.startLng;
        var dist = Math.sqrt(dlat * dlat + dlng * dlng);
        return Math.max(0.05, Math.min(0.5, dist / 300));
    })
    .arcStroke(function(d) {
        return Math.max(0.3, Math.min(1.8, 0.3 + (d.count || 1) * 0.12));
    })
    .arcDashLength(0.6)
    .arcDashGap(0.3)
    .arcDashAnimateTime(function(d) {
        // Faster animation for higher traffic
        return Math.max(1000, 4000 - (d.count || 1) * 200);
    })
    // Rings layer (pulsing rings on threat points and local)
    .ringsData([])
    .ringLat('lat')
    .ringLng('lng')
    .ringAltitude(0.005)
    .ringColor(function(d) { return d.color; })
    .ringMaxRadius(function(d) { return d.isLocal ? 3 : 2.5; })
    .ringPropagationSpeed(function(d) { return d.isLocal ? 2 : 3; })
    .ringRepeatPeriod(function(d) { return d.isLocal ? 1500 : 1200; });

// ── Lighting ───────────────────────────────────────
var scene = globe.scene();
// Remove default lights and add custom ones
var dirLight = new THREE.DirectionalLight(0x6688bb, 0.6);
dirLight.position.set(-1, 1.5, 1);
scene.add(dirLight);

// ── Auto-rotate ────────────────────────────────────
globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.4;
globe.controls().enableDamping = true;
globe.controls().dampingFactor = 0.1;

// Pause auto-rotate on interaction, resume after idle
var idleTimer = null;
document.addEventListener('mousedown', function() {
    globe.controls().autoRotate = false;
    clearTimeout(idleTimer);
});
document.addEventListener('mouseup', function() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function() { globe.controls().autoRotate = true; }, 12000);
});
document.addEventListener('wheel', function() {
    globe.controls().autoRotate = false;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function() { globe.controls().autoRotate = true; }, 12000);
});

// Click background to dismiss detail panel
document.getElementById('globe').addEventListener('click', function(e) {
    if (e.target.tagName === 'CANVAS') {
        // only dismiss if not clicking a point (the onPointClick fires separately)
        setTimeout(function() {
            // small delay so onPointClick can fire first
        }, 50);
    }
});

// ── Set local position ─────────────────────────────
function setLocalPosition(lat, lon) {
    localLat = lat;
    localLon = lon;
    rebuildVisuals();
    // Aim camera at local position
    globe.pointOfView({ lat: lat, lng: lon, altitude: 2.2 }, 1500);
}

// ── Set connections ────────────────────────────────
function setConnections(connsJSON) {
    connectionData = JSON.parse(connsJSON);
    rebuildVisuals();
}

// ── Rebuild all visual layers ──────────────────────
function rebuildVisuals() {
    var newPoints = [];
    var newArcs = [];
    var newRings = [];
    var totalConns = 0;
    var countries = new Set();

    // Local position marker
    newPoints.push({
        lat: localLat,
        lng: localLon,
        color: '#89b4fa',
        isLocal: true,
        count: 0
    });
    newRings.push({
        lat: localLat,
        lng: localLon,
        color: function(t) { return 'rgba(137, 180, 250, ' + (1 - t) + ')'; },
        isLocal: true
    });

    connectionData.forEach(function(c) {
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

        // Endpoint point
        newPoints.push({
            lat: lat,
            lng: lon,
            color: color,
            count: count,
            country: country,
            city: city,
            isp: isp,
            threat: threat,
            isLocal: false
        });

        // Arc from local to endpoint
        newArcs.push({
            startLat: localLat,
            startLng: localLon,
            endLat: lat,
            endLng: lon,
            color: [color + 'CC', color + '44'],
            count: count,
            threat: threat
        });

        // Pulsing ring on threat endpoints
        if (threat) {
            newRings.push({
                lat: lat,
                lng: lon,
                color: function(t) { return 'rgba(243, 139, 168, ' + (1 - t) + ')'; },
                isLocal: false
            });
        }
    });

    // Apply data
    globe.pointsData(newPoints);
    globe.arcsData(newArcs);
    globe.ringsData(newRings);

    // Update overlay stats
    document.getElementById('stat-endpoints').textContent = connectionData.length;
    document.getElementById('stat-connections').textContent = totalConns;
    document.getElementById('stat-countries').textContent = countries.size;
}

// Initialize with default local position
setLocalPosition(37.8, -122.4);
</script>
</body>
</html>"""


class WorldMapWidget(QWidget):
    """Interactive 3D globe map using globe.gl via QWebEngineView."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(500, 280)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._web = QWebEngineView()
        self._web.setHtml(GLOBE_HTML, QUrl("about:blank"))
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
