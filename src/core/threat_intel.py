"""Threat Intelligence Engine — IP/domain reputation scoring and threat alerting."""

import ipaddress
import time
from datetime import datetime

from PySide6.QtCore import QObject, Signal


# ── Local Threat Databases ───────────────────────────────────

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 31337, 1337, 9001, 12345, 54321, 65535,
    8888, 9999, 50050, 50051,  # Cobalt Strike
    1080, 8081,  # Common proxy/malware
}

MALWARE_C2_PORTS = {
    4444,   # Metasploit default
    50050,  # Cobalt Strike
    8080,   # Empire / various
    443,    # HTTPS C2 (combined with other indicators)
    8443,   # Alt HTTPS C2
    1337,   # Leet / hacker convention
    31337,  # Back Orifice
    6667,   # IRC C2
    9001,   # Tor default
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".cc",
    ".su", ".onion", ".bit", ".bazar", ".coin",
}

# Known scanner/research IP ranges (partial CIDRs)
KNOWN_SCANNER_CIDRS = [
    "71.6.135.0/24",    # BinaryEdge
    "71.6.146.0/24",    # BinaryEdge
    "71.6.167.0/24",    # BinaryEdge
    "80.82.77.0/24",    # Censys
    "80.82.78.0/24",    # Censys
    "93.120.27.0/24",   # Censys
    "66.240.192.0/18",  # Shodan
    "198.20.69.0/24",   # Shodan
    "198.20.70.0/24",   # Shodan
    "198.20.99.0/24",   # Shodan
    "162.142.125.0/24", # Censys
    "167.248.133.0/24", # Censys
    "167.94.138.0/24",  # Censys
    "185.142.236.0/24", # Censys
]

# Known high-risk country codes (for scoring, not blocking)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "NG", "RO", "UA", "BY"}

# Suspicious user agents
SUSPICIOUS_UAS = {
    "nmap", "masscan", "zgrab", "censys", "shodan", "nikto",
    "sqlmap", "dirbuster", "gobuster", "hydra", "burp",
    "metasploit", "cobalt", "empire", "mimikatz",
}

# Pre-parse scanner CIDRs
_SCANNER_NETWORKS = []
for cidr in KNOWN_SCANNER_CIDRS:
    try:
        _SCANNER_NETWORKS.append(ipaddress.ip_network(cidr))
    except ValueError:
        pass


class ThreatIntelligence(QObject):
    """Scores IPs and domains for threat level and emits alerts for high-risk entities."""

    threat_scored = Signal(str, int, dict)  # ip, score, details
    threat_alert = Signal(dict)  # security event for high scores

    ALERT_THRESHOLD = 60

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scores: dict[str, int] = {}
        self._score_details: dict[str, dict] = {}
        self._cooldowns: dict[str, float] = {}
        self._cooldown_s = 120.0
        self._geo_cache: dict[str, dict] = {}

    def set_geo_cache(self, cache: dict[str, dict]):
        """Update GeoIP cache reference."""
        self._geo_cache = cache

    def check_connections(self, connections: list[dict]):
        """Score IPs from active connections."""
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            if remote_ip and not self._is_private(remote_ip):
                self._score_ip(remote_ip, remote_port=remote_port)

    def check_domain(self, dns_info: dict):
        """Check DNS query domain against threat intelligence."""
        domain = dns_info.get("query_name", dns_info.get("dns_query", ""))
        src_ip = dns_info.get("src_ip", dns_info.get("src", ""))
        if not domain:
            return

        score = 0
        reasons = []

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 25
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # Very long domain (possible tunneling)
        if len(domain) > 60:
            score += 15
            reasons.append(f"Long domain name ({len(domain)} chars)")

        # High entropy subdomain
        parts = domain.split(".")
        if len(parts) > 2 and len(parts[0]) > 15:
            score += 10
            reasons.append("High-entropy subdomain")

        if score >= 40:
            self._emit_alert(
                rule_id="threat_domain",
                severity="warning",
                title="Suspicious Domain Detected",
                description=f"Domain {domain} scored {score}: {'; '.join(reasons)}",
                src_ip=src_ip,
                evidence=f"Score: {score}, Reasons: {', '.join(reasons)}",
                recommended_action="Investigate DNS traffic and block if confirmed malicious",
            )

    def check_packet(self, pkt_info: dict):
        """Check packet for threat indicators."""
        src = pkt_info.get("src", "")
        dst = pkt_info.get("dst", "")
        dst_port = pkt_info.get("dst_port", 0)

        if src and not self._is_private(src):
            self._score_ip(src, remote_port=dst_port, direction="inbound")
        if dst and not self._is_private(dst):
            self._score_ip(dst, remote_port=dst_port, direction="outbound")

    def _score_ip(self, ip: str, remote_port: int = 0, direction: str = ""):
        """Calculate threat score for an IP address."""
        if ip in self._scores:
            return  # Already scored recently

        score = 0
        reasons = []

        # Check against known scanner ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in _SCANNER_NETWORKS:
                if ip_obj in net:
                    score += 20
                    reasons.append("Known scanner range")
                    break
        except ValueError:
            pass

        # Suspicious port
        if remote_port in SUSPICIOUS_PORTS:
            score += 30
            reasons.append(f"Suspicious port: {remote_port}")
        elif remote_port in MALWARE_C2_PORTS and remote_port not in (443, 8080):
            score += 20
            reasons.append(f"Known C2 port: {remote_port}")

        # GeoIP-based scoring
        geo = self._geo_cache.get(ip, {})
        country_code = geo.get("country_code", "")
        if country_code in HIGH_RISK_COUNTRIES:
            score += 15
            reasons.append(f"High-risk country: {country_code}")

        # Cache the score
        self._scores[ip] = min(score, 100)
        self._score_details[ip] = {"score": score, "reasons": reasons, "country": country_code}

        self.threat_scored.emit(ip, min(score, 100), self._score_details[ip])

        # Alert if high score
        if score >= self.ALERT_THRESHOLD:
            self._emit_alert(
                rule_id="threat_ip",
                severity="warning" if score < 80 else "critical",
                title="High-Threat IP Detected",
                description=f"IP {ip} scored {score}: {'; '.join(reasons)}",
                src_ip=ip if direction == "inbound" else "",
                dst_ip=ip if direction == "outbound" else "",
                evidence=f"Score: {score}, Reasons: {', '.join(reasons)}",
                recommended_action=f"Block IP {ip} at firewall",
            )

    def _emit_alert(self, **kwargs):
        now = time.time()
        key = f"{kwargs.get('rule_id', '')}:{kwargs.get('src_ip', '')}{kwargs.get('dst_ip', '')}"
        if now - self._cooldowns.get(key, 0) < self._cooldown_s:
            return
        self._cooldowns[key] = now

        event = {"timestamp": datetime.now().isoformat()}
        event.update(kwargs)
        self.threat_alert.emit(event)

    def get_overall_threat_level(self) -> int:
        """Return overall network threat level (0-100)."""
        if not self._scores:
            return 0
        top_scores = sorted(self._scores.values(), reverse=True)[:10]
        return min(100, int(sum(top_scores) / max(len(top_scores), 1)))

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True
