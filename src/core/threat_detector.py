"""Real-time packet threat detection engine."""

import json
import math
import time
from collections import defaultdict
from datetime import datetime


SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    5555: "Android ADB debug",
    31337: "Back Orifice trojan",
    6667: "IRC (common C2 channel)",
    6697: "IRC over TLS (C2)",
    1080: "SOCKS proxy",
    9001: "Tor default ORPort",
    9050: "Tor SOCKS proxy",
    12345: "NetBus trojan",
    27374: "SubSeven trojan",
    1337: "Common hacker port",
}

# Expected protocols on well-known ports
# Note: 443 omitted (UDP/QUIC is legitimate), 53 omitted (uses both TCP and UDP)
_EXPECTED_PROTOCOLS = {
    80: "TCP",
    22: "TCP",
    21: "TCP",
    25: "TCP",
    23: "TCP",
}

# Thresholds
_PORT_SCAN_THRESHOLD = 15       # unique ports from same source in window
_PORT_SCAN_WINDOW_S = 60.0
_SYN_FLOOD_THRESHOLD = 100      # SYN-only packets in window
_SYN_FLOOD_WINDOW_S = 10.0
_DNS_FREQ_THRESHOLD = 20        # queries to same domain in window
_DNS_FREQ_WINDOW_S = 60.0
_DNS_SIZE_THRESHOLD = 512       # bytes — suspiciously large DNS packet
_DGA_ENTROPY_THRESHOLD = 4.0
_DGA_LENGTH_THRESHOLD = 20
_NXDOMAIN_THRESHOLD = 10        # NXDOMAIN responses in window
_NXDOMAIN_WINDOW_S = 60.0
_MAX_RAW_PACKETS = 100_000

# Known DNS resolvers — never flag queries to these as DGA
_KNOWN_DNS_RESOLVERS = {
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "8.8.8.8", "8.8.4.4",              # Google DNS
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "9.9.9.9",                          # Quad9
}

# Common TLDs — domains with these TLDs AND english words are likely legit
_WHITELISTED_TLDS = {
    "com", "net", "org", "edu", "gov", "io", "co", "dev", "app",
    "cloud", "me", "info", "tv", "us", "uk", "de", "fr", "jp",
}

# Common English substrings found in legitimate domain labels
_ENGLISH_FRAGMENTS = {
    "cloud", "cdn", "api", "web", "app", "mail", "dev", "data",
    "host", "net", "hub", "lab", "dns", "auth", "log", "git",
    "img", "stat", "code", "docs", "font", "play", "shop", "news",
    "file", "link", "page", "site", "blog", "chat", "live", "user",
    "fast", "edge", "push", "sync", "pool", "node", "core", "test",
    "beta", "prod", "stage", "cache", "proxy", "media", "video",
    "audio", "stream", "track", "click", "event", "pixel", "serve",
    "static", "assets", "content", "service", "update", "download",
    "upload", "storage", "server", "client", "mobile", "desktop",
    "android", "apple", "google", "amazon", "azure", "office",
    "micro", "mozilla", "firefox", "chrome", "safari", "windows",
}


def _has_english_words(label: str) -> bool:
    """Check if a domain label contains common English substrings."""
    lower = label.lower()
    return any(frag in lower for frag in _ENGLISH_FRAGMENTS)


def _get_second_level_label(qname: str) -> str:
    """Extract the second-level label from a FQDN (e.g. 'x8k3m2' from 'x8k3m2.example.com')."""
    parts = qname.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _non_alpha_ratio(label: str) -> float:
    """Return the ratio of non-alpha characters in a string."""
    if not label:
        return 0.0
    non_alpha = sum(1 for c in label if not c.isalpha())
    return non_alpha / len(label)


def _consonant_vowel_ratio(label: str) -> float:
    """Return consonant-to-vowel ratio. High values suggest random strings."""
    vowels = set("aeiou")
    v_count = sum(1 for c in label.lower() if c in vowels)
    c_count = sum(1 for c in label.lower() if c.isalpha() and c not in vowels)
    if v_count == 0:
        return float(c_count) if c_count > 0 else 0.0
    return c_count / v_count


class ThreatDetector:
    """Stateful packet analyzer that detects network security threats."""

    def __init__(self):
        self.reset()

    def reset(self):
        """Clear all tracking state."""
        # Port scan detection: src_ip -> {(dst_port, timestamp), ...}
        self._syn_tracker: dict[str, list[tuple[int, float]]] = defaultdict(list)
        self._port_scan_alerted: set[str] = set()

        # SYN flood detection: src_ip -> [(timestamp), ...]
        self._syn_flood_tracker: dict[str, list[float]] = defaultdict(list)
        self._syn_flood_alerted: set[str] = set()

        # ARP spoof detection: ip -> mac
        self._arp_table: dict[str, str] = {}
        self._arp_spoof_alerted: set[str] = set()

        # DNS tunnel detection: domain -> [timestamps]
        self._dns_query_tracker: dict[str, list[float]] = defaultdict(list)
        self._dns_tunnel_alerted: set[str] = set()

        # DGA detection: already-alerted domains
        self._dga_alerted: set[str] = set()

        # NXDOMAIN tracking: src_ip -> [timestamps]
        self._nxdomain_tracker: dict[str, list[float]] = defaultdict(list)
        self._nxdomain_alerted: set[str] = set()

        # Malicious port tracking: already-alerted (src, dst, port) tuples
        self._malicious_port_alerted: set[tuple] = set()

        # Unusual protocol tracking: already-alerted
        self._unusual_proto_alerted: set[tuple] = set()

        # Top talkers: ip -> {bytes_sent, bytes_recv, packets_sent, packets_recv}
        self._traffic_stats: dict[str, dict] = defaultdict(
            lambda: {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0}
        )

        # Security events from current session
        self._security_events: list[dict] = []

        # Self-scan suppression: skip port_scan/syn_flood during user scans
        self._scan_active: bool = False
        self._scan_source_ip: str = ""
        self._scan_target_ip: str = ""

    def set_scan_active(self, active: bool, source_ip: str = "",
                        target_ip: str = ""):
        """Suppress port_scan/syn_flood alerts during a user-initiated scan.

        Checks both directions: local->target AND target->local (SYN-ACK replies).
        """
        self._scan_active = active
        self._scan_source_ip = source_ip
        self._scan_target_ip = target_ip

    def analyze_packet(self, pkt_dict: dict, raw_pkt=None) -> list[dict]:
        """Analyze a packet and return any security events detected.

        Args:
            pkt_dict: Parsed packet info dict with keys: src, dst, protocol, length, info, etc.
            raw_pkt: Raw scapy packet object (optional, for deep inspection).

        Returns:
            List of security event dicts (may be empty).
        """
        events = []
        now = time.time()
        src = pkt_dict.get("src", "")
        dst = pkt_dict.get("dst", "")
        protocol = pkt_dict.get("protocol", "")
        length = pkt_dict.get("length", 0)
        info = pkt_dict.get("info", "")
        flags = pkt_dict.get("tcp_flags", "")
        dst_port = pkt_dict.get("dst_port")
        src_port = pkt_dict.get("src_port")

        # Update traffic stats
        if src:
            self._traffic_stats[src]["bytes_sent"] += length
            self._traffic_stats[src]["packets_sent"] += 1
        if dst:
            self._traffic_stats[dst]["bytes_recv"] += length
            self._traffic_stats[dst]["packets_recv"] += 1

        # Suppress port_scan/syn_flood during user-initiated scans (both directions)
        _skip_scan_checks = (self._scan_active
                             and (src == self._scan_source_ip
                                  or dst == self._scan_source_ip
                                  or src == self._scan_target_ip
                                  or dst == self._scan_target_ip))

        # Port scan detection (TCP SYN to multiple ports)
        if protocol == "TCP" and dst_port and src and "S" in flags:
            if not _skip_scan_checks:
                events.extend(self._check_port_scan(src, dst, dst_port, now))

        # SYN flood detection
        if protocol == "TCP" and src and flags == "S":
            if not _skip_scan_checks:
                events.extend(self._check_syn_flood(src, dst, now))

        # ARP spoof detection
        if raw_pkt is not None:
            events.extend(self._check_arp_spoof_from_raw(raw_pkt, now))

        # DNS analysis
        if raw_pkt is not None:
            events.extend(self._check_dns(raw_pkt, src, dst, length, now))

        # Unusual protocol on common port
        if dst_port and protocol:
            events.extend(self._check_unusual_protocol(src, dst, dst_port, protocol, now))

        # Malicious port detection
        if dst_port:
            events.extend(self._check_malicious_ports(src, dst, dst_port, now))

        # Store events
        self._security_events.extend(events)
        return events

    def _check_port_scan(self, src: str, dst: str, dport: int, now: float) -> list[dict]:
        """Detect port scanning: many SYN packets to different ports from same source."""
        entries = self._syn_tracker[src]
        # Prune old entries
        entries[:] = [(p, t) for p, t in entries if now - t < _PORT_SCAN_WINDOW_S]
        entries.append((dport, now))

        unique_ports = {p for p, _ in entries}
        if len(unique_ports) > _PORT_SCAN_THRESHOLD and src not in self._port_scan_alerted:
            self._port_scan_alerted.add(src)
            return [{
                "timestamp": datetime.now().isoformat(),
                "severity": "critical",
                "event_type": "port_scan",
                "source_ip": src,
                "dest_ip": dst,
                "description": f"Port scan detected from {src}: {len(unique_ports)} unique ports probed in {_PORT_SCAN_WINDOW_S:.0f}s",
                "raw_details": json.dumps({"ports": sorted(unique_ports)[:50]}),
            }]
        return []

    def _check_syn_flood(self, src: str, dst: str, now: float) -> list[dict]:
        """Detect SYN flood: high volume of SYN-only packets from same source."""
        entries = self._syn_flood_tracker[src]
        entries[:] = [t for t in entries if now - t < _SYN_FLOOD_WINDOW_S]
        entries.append(now)

        if len(entries) > _SYN_FLOOD_THRESHOLD and src not in self._syn_flood_alerted:
            self._syn_flood_alerted.add(src)
            return [{
                "timestamp": datetime.now().isoformat(),
                "severity": "critical",
                "event_type": "syn_flood",
                "source_ip": src,
                "dest_ip": dst,
                "description": f"SYN flood detected from {src}: {len(entries)} SYN packets in {_SYN_FLOOD_WINDOW_S:.0f}s",
                "raw_details": json.dumps({"count": len(entries)}),
            }]
        return []

    def _check_arp_spoof_from_raw(self, raw_pkt, now: float) -> list[dict]:
        """Detect ARP spoofing from raw scapy packet."""
        try:
            from scapy.all import ARP
            if ARP not in raw_pkt:
                return []
            arp = raw_pkt[ARP]
            if arp.op != 2:  # Only check ARP replies
                return []
            src_ip = arp.psrc
            src_mac = arp.hwsrc
            if not src_ip or not src_mac:
                return []
        except (ImportError, AttributeError):
            return []

        if src_ip in self._arp_table:
            existing_mac = self._arp_table[src_ip]
            if existing_mac != src_mac and src_ip not in self._arp_spoof_alerted:
                self._arp_spoof_alerted.add(src_ip)
                return [{
                    "timestamp": datetime.now().isoformat(),
                    "severity": "critical",
                    "event_type": "arp_spoof",
                    "source_ip": src_ip,
                    "dest_ip": "",
                    "description": (
                        f"ARP spoofing detected for {src_ip}: "
                        f"MAC changed from {existing_mac} to {src_mac}"
                    ),
                    "raw_details": json.dumps({
                        "ip": src_ip, "old_mac": existing_mac, "new_mac": src_mac
                    }),
                }]
        self._arp_table[src_ip] = src_mac
        return []

    def _check_dns(self, raw_pkt, src: str, dst: str, pkt_len: int,
                   now: float) -> list[dict]:
        """Analyze DNS packets for tunneling, DGA, and NXDOMAIN abuse."""
        events = []
        try:
            from scapy.all import DNS, DNSQR, DNSRR
            if DNS not in raw_pkt:
                return []
            dns = raw_pkt[DNS]
        except (ImportError, AttributeError):
            return []

        # Extract query name
        qname = ""
        if dns.qd and hasattr(dns.qd, "qname"):
            qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")

        if not qname:
            return events

        # DNS tunneling: large packets
        if pkt_len > _DNS_SIZE_THRESHOLD and qname not in self._dns_tunnel_alerted:
            self._dns_tunnel_alerted.add(qname)
            events.append({
                "timestamp": datetime.now().isoformat(),
                "severity": "warning",
                "event_type": "dns_tunnel",
                "source_ip": src,
                "dest_ip": dst,
                "description": f"Suspiciously large DNS packet ({pkt_len} bytes) for {qname}",
                "raw_details": json.dumps({"domain": qname, "size": pkt_len}),
            })

        # Skip frequency, DGA, and NXDOMAIN checks for reverse DNS lookups
        # (e.g. 171.50.168.192.in-addr.arpa, *.ip6.arpa)
        _is_reverse_dns = (qname.endswith(".in-addr.arpa")
                           or qname.endswith(".ip6.arpa"))

        # DNS tunneling: high frequency queries to same domain
        if not _is_reverse_dns:
            base_domain = _extract_base_domain(qname)
            tracker = self._dns_query_tracker[base_domain]
            tracker[:] = [t for t in tracker if now - t < _DNS_FREQ_WINDOW_S]
            tracker.append(now)

            if (len(tracker) > _DNS_FREQ_THRESHOLD
                    and base_domain not in self._dns_tunnel_alerted):
                self._dns_tunnel_alerted.add(base_domain)
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "severity": "warning",
                    "event_type": "dns_tunnel",
                    "source_ip": src,
                    "dest_ip": dst,
                    "description": (
                        f"High-frequency DNS queries to {base_domain}: "
                        f"{len(tracker)} queries in {_DNS_FREQ_WINDOW_S:.0f}s"
                    ),
                    "raw_details": json.dumps({"domain": base_domain, "count": len(tracker)}),
                })

        # DGA detection: multi-criteria check on second-level domain label
        if not _is_reverse_dns and qname not in self._dga_alerted:
            # Skip if querying a known DNS resolver
            if dst not in _KNOWN_DNS_RESOLVERS:
                sld = _get_second_level_label(qname)
                parts = qname.rstrip(".").split(".")
                tld = parts[-1].lower() if parts else ""

                # Only evaluate if the second-level label is long enough
                if len(sld) > _DGA_LENGTH_THRESHOLD:
                    sld_entropy = _shannon_entropy(sld)
                    na_ratio = _non_alpha_ratio(sld)
                    cv_ratio = _consonant_vowel_ratio(sld)

                    # Skip if TLD is whitelisted AND label has english words
                    is_legit = (tld in _WHITELISTED_TLDS
                                and _has_english_words(sld))

                    # Flag only if: high entropy AND high non-alpha ratio
                    # OR extremely high consonant-to-vowel ratio
                    if (not is_legit
                            and sld_entropy > _DGA_ENTROPY_THRESHOLD
                            and (na_ratio >= 0.3 or cv_ratio > 5.0)):
                        self._dga_alerted.add(qname)
                        events.append({
                            "timestamp": datetime.now().isoformat(),
                            "severity": "warning",
                            "event_type": "dga_suspect",
                            "source_ip": src,
                            "dest_ip": dst,
                            "description": (
                                f"Possible DGA domain: {qname} "
                                f"(label entropy: {sld_entropy:.2f}, "
                                f"non-alpha: {na_ratio:.0%}, "
                                f"C/V ratio: {cv_ratio:.1f})"
                            ),
                            "raw_details": json.dumps({
                                "domain": qname,
                                "label": sld,
                                "entropy": round(sld_entropy, 2),
                                "non_alpha_ratio": round(na_ratio, 2),
                                "cv_ratio": round(cv_ratio, 1),
                            }),
                        })

        # NXDOMAIN abuse detection
        rcode = dns.rcode if hasattr(dns, "rcode") else 0
        if rcode == 3:  # NXDOMAIN
            nx_entries = self._nxdomain_tracker[src]
            nx_entries[:] = [t for t in nx_entries if now - t < _NXDOMAIN_WINDOW_S]
            nx_entries.append(now)

            if len(nx_entries) > _NXDOMAIN_THRESHOLD and src not in self._nxdomain_alerted:
                self._nxdomain_alerted.add(src)
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "severity": "warning",
                    "event_type": "excessive_nxdomain",
                    "source_ip": src,
                    "dest_ip": dst,
                    "description": (
                        f"Excessive NXDOMAIN responses to {src}: "
                        f"{len(nx_entries)} in {_NXDOMAIN_WINDOW_S:.0f}s"
                    ),
                    "raw_details": json.dumps({"count": len(nx_entries)}),
                })

        return events

    def _check_unusual_protocol(self, src: str, dst: str, dport: int,
                                protocol: str, now: float) -> list[dict]:
        """Flag unexpected protocols on well-known ports."""
        expected = _EXPECTED_PROTOCOLS.get(dport)
        if expected and protocol != expected:
            key = (src, dst, dport)
            if key not in self._unusual_proto_alerted:
                self._unusual_proto_alerted.add(key)
                return [{
                    "timestamp": datetime.now().isoformat(),
                    "severity": "warning",
                    "event_type": "unusual_protocol",
                    "source_ip": src,
                    "dest_ip": dst,
                    "description": (
                        f"Unexpected {protocol} traffic on port {dport} "
                        f"(expected {expected}) from {src} to {dst}"
                    ),
                    "raw_details": json.dumps({
                        "port": dport, "expected": expected, "actual": protocol
                    }),
                }]
        return []

    def _check_malicious_ports(self, src: str, dst: str, dport: int,
                               now: float) -> list[dict]:
        """Flag connections to known suspicious ports."""
        if dport in SUSPICIOUS_PORTS:
            key = (src, dst, dport)
            if key not in self._malicious_port_alerted:
                self._malicious_port_alerted.add(key)
                reason = SUSPICIOUS_PORTS[dport]
                return [{
                    "timestamp": datetime.now().isoformat(),
                    "severity": "critical",
                    "event_type": "malicious_port",
                    "source_ip": src,
                    "dest_ip": dst,
                    "description": (
                        f"Connection to suspicious port {dport} ({reason}): "
                        f"{src} -> {dst}:{dport}"
                    ),
                    "raw_details": json.dumps({
                        "port": dport, "reason": reason
                    }),
                }]
        return []

    def get_top_talkers(self, limit: int = 10) -> list[dict]:
        """Return IPs sorted by total traffic volume."""
        result = []
        for ip, stats in self._traffic_stats.items():
            total = stats["bytes_sent"] + stats["bytes_recv"]
            result.append({
                "ip": ip,
                "bytes_sent": stats["bytes_sent"],
                "bytes_recv": stats["bytes_recv"],
                "bytes_total": total,
                "packets_sent": stats["packets_sent"],
                "packets_recv": stats["packets_recv"],
            })
        result.sort(key=lambda x: x["bytes_total"], reverse=True)
        return result[:limit]

    def get_security_events(self) -> list[dict]:
        """Return all security events detected in the current session."""
        return list(self._security_events)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s.lower():
        if c != ".":
            freq[c] += 1
    length = sum(freq.values())
    if length == 0:
        return 0.0
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _extract_base_domain(fqdn: str) -> str:
    """Extract base domain from FQDN (last two labels)."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn
