"""Interactive network topology using QWebEngineView + vis.js Network."""

from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QVBoxLayout, QWidget


VISJS_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { width: 100%; height: 100%; background: #11111b; overflow: hidden; }
  #network { width: 100%; height: 100%; }

  /* Info overlay */
  #info-overlay {
    position: absolute;
    top: 10px; left: 10px;
    z-index: 10;
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
  #info-overlay .stat { color: #a6adc8; }
  #info-overlay .stat b { color: #cdd6f4; }

  /* Node detail panel */
  #detail-panel {
    display: none;
    position: absolute;
    bottom: 10px; right: 10px;
    z-index: 10;
    background: rgba(30,30,46,0.95);
    border: 1px solid #45475a;
    border-radius: 8px;
    padding: 12px 16px;
    color: #cdd6f4;
    font-family: "Consolas", monospace;
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
</style>
</head>
<body>
<div id="network"></div>
<div id="info-overlay">
  <div class="title">NETWORK TOPOLOGY</div>
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

<script>
var container = document.getElementById('network');
var nodes = new vis.DataSet();
var edges = new vis.DataSet();

var deviceColors = {
    'router':  { bg: '#f9e2af', border: '#dfc48a', font: '#1e1e2e', shape: 'diamond', size: 30 },
    'server':  { bg: '#89b4fa', border: '#6a96dc', font: '#1e1e2e', shape: 'square',  size: 25 },
    'computer':{ bg: '#a6e3a1', border: '#88c584', font: '#1e1e2e', shape: 'dot',     size: 22 },
    'phone':   { bg: '#cba6f7', border: '#ad88d9', font: '#1e1e2e', shape: 'triangle', size: 20 },
    'printer': { bg: '#94e2d5', border: '#76c4b7', font: '#1e1e2e', shape: 'star',    size: 20 },
    'unknown': { bg: '#585b70', border: '#45475a', font: '#cdd6f4', shape: 'dot',     size: 18 }
};

var options = {
    physics: {
        enabled: true,
        barnesHut: {
            gravitationalConstant: -3000,
            centralGravity: 0.15,
            springLength: 120,
            springConstant: 0.04,
            damping: 0.09,
            avoidOverlap: 0.3
        },
        stabilization: { iterations: 150, fit: true }
    },
    interaction: {
        hover: true,
        tooltipDelay: 100,
        dragNodes: true,
        dragView: true,
        zoomView: true,
        navigationButtons: false
    },
    edges: {
        smooth: { type: 'continuous', roundness: 0.3 },
        color: { color: '#45475a', highlight: '#89b4fa', hover: '#585b70' },
        width: 1.5,
        hoverWidth: 2.5
    },
    nodes: {
        borderWidth: 2,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 10 },
        font: { color: '#cdd6f4', size: 11, face: 'Consolas' }
    }
};

var network = new vis.Network(container, { nodes: nodes, edges: edges }, options);
var deviceDataMap = {};

// Click handler - show detail panel
network.on('click', function(params) {
    var panel = document.getElementById('detail-panel');
    if (params.nodes.length > 0) {
        var nodeId = params.nodes[0];
        var data = deviceDataMap[nodeId] || {};
        document.getElementById('detail-title').textContent = data.hostname || data.ip || nodeId;
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
        document.getElementById('detail-content').innerHTML = html;
        panel.style.display = 'block';
    } else {
        panel.style.display = 'none';
    }
});

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
    var existingIds = nodes.getIds();
    var newIds = [];
    var routerId = null;
    var onlineCount = 0;

    devices.forEach(function(dev) {
        var ip = dev.ip || '';
        if (!ip) return;
        newIds.push(ip);
        deviceDataMap[ip] = dev;

        var dtype = classifyDevice(dev);
        var cfg = deviceColors[dtype] || deviceColors['unknown'];
        var label = dev.hostname || ip;
        if (label.length > 20) label = label.substring(0, 17) + '...';
        var isOnline = dev.is_online !== false && dev.is_online !== 0;
        if (isOnline) onlineCount++;

        if (dtype === 'router' && !routerId) routerId = ip;

        var nodeData = {
            id: ip,
            label: label,
            shape: cfg.shape,
            size: cfg.size,
            color: {
                background: isOnline ? cfg.bg : '#45475a',
                border: isOnline ? cfg.border : '#313244',
                highlight: { background: '#89b4fa', border: '#6a96dc' },
                hover: { background: cfg.bg, border: '#89b4fa' }
            },
            font: { color: isOnline ? cfg.font : '#585b70' },
            opacity: isOnline ? 1.0 : 0.5
        };

        if (existingIds.indexOf(ip) >= 0) {
            nodes.update(nodeData);
        } else {
            nodes.add(nodeData);
        }
    });

    // Remove stale nodes
    existingIds.forEach(function(id) {
        if (newIds.indexOf(id) < 0) {
            nodes.remove(id);
        }
    });

    // Build star topology from router
    edges.clear();
    if (routerId) {
        newIds.forEach(function(id) {
            if (id !== routerId) {
                edges.add({ from: routerId, to: id, id: routerId + '-' + id });
            }
        });
    }

    // Update stats
    document.getElementById('stat-nodes').textContent = newIds.length;
    document.getElementById('stat-edges').textContent = edges.length;
    document.getElementById('stat-online').textContent = onlineCount;
}

function addTrafficEdges(edgesJSON) {
    var newEdges = JSON.parse(edgesJSON);
    var existingEdgeIds = edges.getIds();

    newEdges.forEach(function(e) {
        var edgeId = e.src + '-' + e.dst;
        var reverseId = e.dst + '-' + e.src;
        if (existingEdgeIds.indexOf(edgeId) < 0 && existingEdgeIds.indexOf(reverseId) < 0) {
            var weight = e.weight || 1;
            var width = Math.max(1, Math.min(6, 1 + Math.log2(weight / 10000)));
            edges.add({
                id: edgeId,
                from: e.src,
                to: e.dst,
                width: width,
                color: { color: '#585b70', highlight: '#89b4fa' },
                dashes: true
            });
        }
    });
}
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
    """Interactive network topology using vis.js via QWebEngineView."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 280)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._web = QWebEngineView()
        self._web.setHtml(VISJS_HTML, QUrl("about:blank"))
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
