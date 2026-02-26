"""Interactive 3D network topology using QWebEngineView + 3d-force-graph (Three.js)."""

from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QVBoxLayout, QWidget


FORCE3D_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
<script src="https://unpkg.com/three@0.160.0/examples/js/renderers/CSS2DRenderer.js"></script>
<script src="https://unpkg.com/3d-force-graph@1.73.3/dist/3d-force-graph.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { width: 100%; height: 100%; background: #0a0a14; overflow: hidden; font-family: "Consolas", monospace; }
  #graph { width: 100%; height: 100%; }

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

  /* Node detail panel */
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
    min-width: 200px;
    max-width: 300px;
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
<div id="graph"></div>
<div id="info-overlay">
  <div class="title">3D NETWORK TOPOLOGY</div>
  <div class="stat">Nodes: <b id="stat-nodes">0</b></div>
  <div class="stat">Edges: <b id="stat-edges">0</b></div>
  <div class="stat">Online: <b id="stat-online">0</b></div>
</div>
<div id="detail-panel">
  <div class="detail-title" id="detail-title"></div>
  <div id="detail-content"></div>
</div>
<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#f9e2af;"></div> Router</div>
  <div class="legend-item"><div class="legend-dot" style="background:#89b4fa;"></div> Server</div>
  <div class="legend-item"><div class="legend-dot" style="background:#a6e3a1;"></div> Computer</div>
  <div class="legend-item"><div class="legend-dot" style="background:#cba6f7;"></div> Phone</div>
  <div class="legend-item"><div class="legend-dot" style="background:#94e2d5;"></div> Printer</div>
  <div class="legend-item"><div class="legend-dot" style="background:#585b70;"></div> Unknown</div>
</div>
<div id="controls-hint">
  LMB drag: rotate &bull; RMB drag: pan<br/>
  Scroll: zoom &bull; Click node: details
</div>

<script>
var deviceColors = {
    'router':  { bg: '#f9e2af', glow: '#f9e2af', size: 8  },
    'server':  { bg: '#89b4fa', glow: '#89b4fa', size: 7  },
    'computer':{ bg: '#a6e3a1', glow: '#a6e3a1', size: 6  },
    'phone':   { bg: '#cba6f7', glow: '#cba6f7', size: 5.5},
    'printer': { bg: '#94e2d5', glow: '#94e2d5', size: 5.5},
    'unknown': { bg: '#585b70', glow: '#585b70', size: 4.5}
};

var deviceShapes = {
    'router':  'diamond',
    'server':  'cube',
    'computer':'sphere',
    'phone':   'cone',
    'printer': 'octahedron',
    'unknown': 'sphere'
};

var deviceDataMap = {};
var graphData = { nodes: [], links: [] };

// Initialize 3D Force Graph
var Graph = ForceGraph3D()(document.getElementById('graph'))
    .backgroundColor('#0a0a14')
    .showNavInfo(false)
    .nodeLabel(function(node) { return ''; })  // We use click panel instead
    .nodeVal(function(node) { return node.size || 5; })
    .nodeColor(function(node) { return node.color || '#585b70'; })
    .nodeOpacity(0.95)
    .nodeResolution(16)
    .nodeThreeObject(function(node) {
        var cfg = deviceColors[node.dtype] || deviceColors['unknown'];
        var shape = deviceShapes[node.dtype] || 'sphere';
        var sz = cfg.size;
        var isOnline = node.isOnline;
        var color = new THREE.Color(isOnline ? cfg.bg : '#45475a');
        var glowColor = new THREE.Color(isOnline ? cfg.glow : '#313244');

        var material = new THREE.MeshPhongMaterial({
            color: color,
            emissive: glowColor,
            emissiveIntensity: isOnline ? 0.4 : 0.1,
            shininess: 80,
            transparent: !isOnline,
            opacity: isOnline ? 1.0 : 0.4
        });

        var geometry;
        switch (shape) {
            case 'diamond':
                geometry = new THREE.OctahedronGeometry(sz, 0);
                geometry.applyMatrix4(new THREE.Matrix4().makeScale(1, 1.5, 1));
                break;
            case 'cube':
                geometry = new THREE.BoxGeometry(sz * 1.3, sz * 1.3, sz * 1.3);
                break;
            case 'cone':
                geometry = new THREE.ConeGeometry(sz * 0.7, sz * 1.8, 8);
                break;
            case 'octahedron':
                geometry = new THREE.OctahedronGeometry(sz, 0);
                break;
            default:
                geometry = new THREE.SphereGeometry(sz, 16, 16);
        }

        var mesh = new THREE.Mesh(geometry, material);

        // Add glow sprite for online devices
        if (isOnline) {
            var spriteMat = new THREE.SpriteMaterial({
                map: createGlowTexture(cfg.glow),
                transparent: true,
                opacity: 0.3,
                depthWrite: false
            });
            var sprite = new THREE.Sprite(spriteMat);
            sprite.scale.set(sz * 4, sz * 4, 1);
            mesh.add(sprite);
        }

        // Add text label
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        canvas.width = 256;
        canvas.height = 64;
        ctx.font = '24px Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = isOnline ? '#cdd6f4' : '#585b70';
        var label = node.label || node.id;
        if (label.length > 20) label = label.substring(0, 17) + '...';
        ctx.fillText(label, 128, 40);

        var texture = new THREE.CanvasTexture(canvas);
        texture.minFilter = THREE.LinearFilter;
        var labelMat = new THREE.SpriteMaterial({
            map: texture,
            transparent: true,
            depthWrite: false
        });
        var labelSprite = new THREE.Sprite(labelMat);
        labelSprite.scale.set(sz * 5, sz * 1.25, 1);
        labelSprite.position.y = -sz * 1.8;
        mesh.add(labelSprite);

        return mesh;
    })
    .linkColor(function(link) {
        return link.threat ? '#f38ba8' : (link.dashed ? '#585b70' : '#45475a');
    })
    .linkWidth(function(link) { return link.width || 0.8; })
    .linkOpacity(0.6)
    .linkDirectionalParticles(function(link) { return link.traffic ? 3 : 0; })
    .linkDirectionalParticleWidth(1.5)
    .linkDirectionalParticleSpeed(0.006)
    .linkDirectionalParticleColor(function(link) {
        return link.threat ? '#f38ba8' : '#89b4fa';
    })
    .onNodeClick(function(node) {
        var panel = document.getElementById('detail-panel');
        var data = deviceDataMap[node.id] || {};
        document.getElementById('detail-title').textContent = data.hostname || data.ip || node.id;
        var html = '';
        html += '<div class="detail-row">IP: <b>' + (data.ip || 'N/A') + '</b></div>';
        html += '<div class="detail-row">MAC: <b>' + (data.mac || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Hostname: <b>' + (data.hostname || 'N/A') + '</b></div>';
        html += '<div class="detail-row">OS: <b>' + (data.os_info || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Vendor: <b>' + (data.vendor || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Status: <b style="color:' +
                (data.is_online ? '#a6e3a1' : '#f38ba8') + '">' +
                (data.is_online ? 'ONLINE' : 'OFFLINE') + '</b></div>';
        html += '<div class="detail-row">First Seen: <b>' + (data.first_seen || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Last Seen: <b>' + (data.last_seen || 'N/A') + '</b></div>';
        html += '<div class="detail-row">Type: <b style="text-transform:capitalize;">' + (node.dtype || 'unknown') + '</b></div>';
        document.getElementById('detail-content').innerHTML = html;
        panel.style.display = 'block';

        // Focus camera on clicked node
        var distance = 120;
        var distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
        Graph.cameraPosition(
            { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
            node,
            1200
        );
    })
    .onBackgroundClick(function() {
        document.getElementById('detail-panel').style.display = 'none';
    })
    .d3Force('charge').strength(-80);

// Increase link distance
Graph.d3Force('link').distance(60);

// Add center force
Graph.d3Force('center', d3.forceCenter());

// Lighting setup
var scene = Graph.scene();
var ambient = new THREE.AmbientLight(0x404060, 1.2);
scene.add(ambient);
var dirLight = new THREE.DirectionalLight(0x8888cc, 0.8);
dirLight.position.set(100, 200, 150);
scene.add(dirLight);
var pointLight = new THREE.PointLight(0x89b4fa, 0.6, 500);
pointLight.position.set(0, 100, 0);
scene.add(pointLight);

// Add subtle star field background
(function() {
    var starGeo = new THREE.BufferGeometry();
    var positions = new Float32Array(3000);
    for (var i = 0; i < 3000; i++) {
        positions[i] = (Math.random() - 0.5) * 2000;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    var starMat = new THREE.PointsMaterial({
        color: 0x445577,
        size: 0.8,
        transparent: true,
        opacity: 0.6
    });
    scene.add(new THREE.Points(starGeo, starMat));
})();

// Add a subtle grid plane
(function() {
    var gridHelper = new THREE.GridHelper(400, 40, 0x1a1a3e, 0x111128);
    gridHelper.position.y = -80;
    gridHelper.material.transparent = true;
    gridHelper.material.opacity = 0.3;
    scene.add(gridHelper);
})();

// Glow texture generator
function createGlowTexture(colorHex) {
    var canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    var ctx = canvas.getContext('2d');
    var gradient = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
    gradient.addColorStop(0, colorHex);
    gradient.addColorStop(0.3, colorHex + '80');
    gradient.addColorStop(1, colorHex + '00');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 128, 128);
    var texture = new THREE.CanvasTexture(canvas);
    return texture;
}

// Device classifier (same logic as Python side)
function classifyDevice(dev) {
    var ip = dev.ip || '';
    var vendor = (dev.vendor || '').toLowerCase();
    var hostname = (dev.hostname || '').toLowerCase();
    var os_info = (dev.os_info || '').toLowerCase();

    if (ip.endsWith('.1') || ip.endsWith('.254')) return 'router';
    var routerVendors = ['cisco','netgear','linksys','tp-link','asus','ubiquiti','mikrotik','aruba','juniper'];
    for (var i = 0; i < routerVendors.length; i++) {
        if (vendor.indexOf(routerVendors[i]) >= 0) return 'router';
    }
    if (os_info.indexOf('network equipment') >= 0) return 'router';

    var phoneVendors = ['apple','samsung','huawei','xiaomi','oneplus','google'];
    for (var i = 0; i < phoneVendors.length; i++) {
        if (vendor.indexOf(phoneVendors[i]) >= 0) {
            if (hostname.indexOf('phone') >= 0 || hostname.indexOf('iphone') >= 0 || hostname.indexOf('android') >= 0)
                return 'phone';
        }
    }

    var printerVendors = ['hp','epson','canon','brother','lexmark'];
    for (var i = 0; i < printerVendors.length; i++) {
        if (vendor.indexOf(printerVendors[i]) >= 0) return 'printer';
    }
    if (hostname.indexOf('printer') >= 0 || hostname.indexOf('print') >= 0) return 'printer';

    if (hostname.indexOf('server') >= 0 || hostname.indexOf('nas') >= 0 || hostname.indexOf('docker') >= 0)
        return 'server';

    if (os_info || hostname) return 'computer';
    return 'unknown';
}

function setDevices(devicesJSON) {
    var devices = JSON.parse(devicesJSON);
    var newNodes = [];
    var newLinks = [];
    var routerId = null;
    var onlineCount = 0;

    devices.forEach(function(dev) {
        var ip = dev.ip || '';
        if (!ip) return;
        deviceDataMap[ip] = dev;

        var dtype = classifyDevice(dev);
        var cfg = deviceColors[dtype] || deviceColors['unknown'];
        var label = dev.hostname || ip;
        var isOnline = dev.is_online !== false && dev.is_online !== 0;
        if (isOnline) onlineCount++;

        if (dtype === 'router' && !routerId) routerId = ip;

        // Preserve existing positions if node already exists
        var existing = graphData.nodes.find(function(n) { return n.id === ip; });
        var nodeData = {
            id: ip,
            label: label,
            dtype: dtype,
            size: cfg.size,
            color: isOnline ? cfg.bg : '#45475a',
            isOnline: isOnline
        };
        if (existing) {
            nodeData.x = existing.x;
            nodeData.y = existing.y;
            nodeData.z = existing.z;
            nodeData.vx = existing.vx;
            nodeData.vy = existing.vy;
            nodeData.vz = existing.vz;
        }
        newNodes.push(nodeData);
    });

    // Build star topology from router
    if (routerId) {
        newNodes.forEach(function(node) {
            if (node.id !== routerId) {
                newLinks.push({
                    source: routerId,
                    target: node.id,
                    width: 0.8,
                    traffic: node.isOnline
                });
            }
        });
    }

    graphData = { nodes: newNodes, links: newLinks };
    Graph.graphData(graphData);

    // Update stats
    document.getElementById('stat-nodes').textContent = newNodes.length;
    document.getElementById('stat-edges').textContent = newLinks.length;
    document.getElementById('stat-online').textContent = onlineCount;
}

function addTrafficEdges(edgesJSON) {
    var newEdges = JSON.parse(edgesJSON);
    var currentLinks = graphData.links.slice();
    var existingSet = {};
    currentLinks.forEach(function(l) {
        var s = (typeof l.source === 'object') ? l.source.id : l.source;
        var t = (typeof l.target === 'object') ? l.target.id : l.target;
        existingSet[s + '-' + t] = true;
        existingSet[t + '-' + s] = true;
    });

    newEdges.forEach(function(e) {
        var edgeId = e.src + '-' + e.dst;
        var reverseId = e.dst + '-' + e.src;
        if (!existingSet[edgeId] && !existingSet[reverseId]) {
            var weight = e.weight || 1;
            var width = Math.max(0.5, Math.min(4, 0.5 + Math.log2(weight / 10000)));
            currentLinks.push({
                source: e.src,
                target: e.dst,
                width: width,
                dashed: true,
                traffic: true
            });
            existingSet[edgeId] = true;
        }
    });

    graphData.links = currentLinks;
    Graph.graphData(graphData);
}

// Slow rotation when idle
var autoRotate = true;
var angle = 0;
(function rotate() {
    if (autoRotate && graphData.nodes.length > 0) {
        angle += 0.002;
        var dist = 250;
        Graph.cameraPosition({
            x: dist * Math.sin(angle),
            z: dist * Math.cos(angle)
        });
    }
    requestAnimationFrame(rotate);
})();

// Stop auto-rotate on user interaction, resume after idle
var idleTimer = null;
document.addEventListener('mousedown', function() {
    autoRotate = false;
    clearTimeout(idleTimer);
});
document.addEventListener('mouseup', function() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function() { autoRotate = true; }, 15000);
});
document.addEventListener('wheel', function() {
    autoRotate = false;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function() { autoRotate = true; }, 15000);
});
</script>
</body>
</html>"""


# Device type classification (kept for Python-side use)
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

    if ip.endswith(".1") or ip.endswith(".254"):
        return "router"
    if any(kw in vendor for kw in ("cisco", "netgear", "linksys", "tp-link", "asus",
                                    "ubiquiti", "mikrotik", "aruba", "juniper")):
        return "router"
    if "network equipment" in os_info:
        return "router"
    if any(kw in vendor for kw in ("apple", "samsung", "huawei", "xiaomi", "oneplus", "google")):
        if "phone" in hostname or "iphone" in hostname or "android" in hostname:
            return "phone"
    if any(kw in vendor for kw in ("hp", "epson", "canon", "brother", "lexmark")):
        return "printer"
    if "printer" in hostname or "print" in hostname:
        return "printer"
    if "server" in hostname or "nas" in hostname or "docker" in hostname:
        return "server"
    if os_info or hostname:
        return "computer"
    return "unknown"


class TopologyMapWidget(QWidget):
    """Interactive 3D network topology using 3d-force-graph via QWebEngineView."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 280)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._web = QWebEngineView()
        self._web.setHtml(FORCE3D_HTML, QUrl("about:blank"))
        layout.addWidget(self._web)

        self._page_loaded = False
        self._pending_devices = None
        self._web.loadFinished.connect(self._on_load)

    def _on_load(self, ok: bool):
        if ok:
            self._page_loaded = True
            if self._pending_devices is not None:
                self._push_devices(self._pending_devices)
                self._pending_devices = None

    def _run_js(self, js: str):
        if self._page_loaded:
            self._web.page().runJavaScript(js)

    def set_devices(self, devices: list[dict]):
        if not self._page_loaded:
            self._pending_devices = devices
            return
        self._push_devices(devices)

    def _push_devices(self, devices: list[dict]):
        import json
        data = json.dumps(devices)
        escaped = data.replace("\\", "\\\\").replace("'", "\\'")
        self._run_js(f"setDevices('{escaped}');")

    def set_traffic_edges(self, edges: list[tuple[str, str, float]]):
        import json
        edge_dicts = [{"src": s, "dst": d, "weight": w} for s, d, w in edges]
        data = json.dumps(edge_dicts)
        escaped = data.replace("\\", "\\\\").replace("'", "\\'")
        self._run_js(f"addTrafficEdges('{escaped}');")
