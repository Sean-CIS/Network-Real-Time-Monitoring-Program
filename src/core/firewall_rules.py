"""Generate firewall rule suggestions from security events."""


def generate_rule(event: dict) -> dict:
    """Generate firewall rules from a security event.

    Returns dict with keys:
        linux: str    — iptables command
        windows: str  — netsh advfirewall command
        desc: str     — human-readable description
    """
    event_type = event.get("event_type", "")
    source_ip = event.get("source_ip", "")
    dest_ip = event.get("dest_ip", "")

    if event_type in ("port_scan", "syn_flood") and source_ip:
        return _block_source(source_ip, event_type)

    if event_type == "malicious_port":
        raw = event.get("raw_details", "")
        port = _extract_port(raw)
        if port and dest_ip:
            return _block_port(dest_ip, port, event_type)
        elif source_ip:
            return _block_source(source_ip, event_type)

    if event_type == "arp_spoof" and source_ip:
        return _block_source(source_ip, event_type)

    if source_ip:
        return _block_source(source_ip, event_type)

    return {
        "linux": "# No specific rule could be generated for this event",
        "windows": "REM No specific rule could be generated for this event",
        "desc": "Unable to generate a specific firewall rule for this event.",
    }


def _block_source(ip: str, reason: str) -> dict:
    """Block all traffic from a source IP."""
    return {
        "linux": f"sudo iptables -A INPUT -s {ip} -j DROP",
        "windows": (
            f'netsh advfirewall firewall add rule name="Block {ip} ({reason})" '
            f'dir=in action=block remoteip={ip}'
        ),
        "desc": f"Block all incoming traffic from {ip} (reason: {reason}).",
    }


def _block_port(ip: str, port: int, reason: str) -> dict:
    """Block traffic to a specific port/IP combination."""
    return {
        "linux": f"sudo iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP",
        "windows": (
            f'netsh advfirewall firewall add rule name="Block port {port} to {ip}" '
            f'dir=out action=block remoteip={ip} remoteport={port} protocol=tcp'
        ),
        "desc": f"Block outbound TCP traffic to {ip}:{port} (reason: {reason}).",
    }


def _extract_port(raw_details: str) -> int | None:
    """Extract port number from raw_details JSON string."""
    try:
        import json
        data = json.loads(raw_details) if isinstance(raw_details, str) else raw_details
        port = data.get("port")
        return int(port) if port else None
    except (ValueError, TypeError, AttributeError):
        return None
