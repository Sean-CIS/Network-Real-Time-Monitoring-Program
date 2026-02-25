"""SET Defense Toolkit — the opposite of Kali's Social Engineering Toolkit.

Defensive counterpart to SET: detects phishing, credential leaks, payload delivery,
DNS poisoning, rogue APs, and C2 beaconing patterns.
"""

import re
import time
from collections import defaultdict, deque
from datetime import datetime

from PySide6.QtCore import QObject, Signal

from src.utils import db

# ── Popular domains to monitor for typosquatting ──────────────
PROTECTED_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "github.com", "dropbox.com", "yahoo.com", "outlook.com", "gmail.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "americanexpress.com", "stripe.com", "shopify.com", "slack.com",
    "zoom.us", "office.com", "live.com", "icloud.com", "adobe.com",
    "wordpress.com", "cloudflare.com", "aws.amazon.com", "azure.com",
    "salesforce.com", "twilio.com", "okta.com", "duo.com", "lastpass.com",
    "1password.com", "bitwarden.com", "protonmail.com", "signal.org",
    "whatsapp.com", "telegram.org", "reddit.com", "stackoverflow.com",
    "docker.com", "kubernetes.io", "npmjs.com", "pypi.org",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    "youtube.com", "tiktok.com", "spotify.com", "twitch.tv",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com",
    "airbnb.com", "booking.com", "expedia.com",
    "coinbase.com", "binance.com", "kraken.com",
    "robinhood.com", "etrade.com", "fidelity.com", "schwab.com",
    "usps.com", "ups.com", "fedex.com", "dhl.com",
    "irs.gov", "ssa.gov", "dmv.gov",
    "att.com", "verizon.com", "tmobile.com", "comcast.com", "spectrum.com",
    "samsung.com", "dell.com", "hp.com", "lenovo.com",
    "nvidia.com", "amd.com", "intel.com",
    "oracle.com", "sap.com", "ibm.com", "vmware.com",
    "cisco.com", "paloaltonetworks.com", "fortinet.com", "crowdstrike.com",
]

# PowerShell download cradle patterns
POWERSHELL_PATTERNS = [
    rb"(?i)invoke-expression",
    rb"(?i)IEX\s*\(",
    rb"(?i)downloadstring",
    rb"(?i)downloadfile",
    rb"(?i)net\.webclient",
    rb"(?i)start-bitstransfer",
    rb"(?i)invoke-webrequest",
    rb"(?i)\-enc\s+[A-Za-z0-9+/=]{20,}",
    rb"(?i)frombase64string",
    rb"(?i)invoke-shellcode",
    rb"(?i)invoke-mimikatz",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


class SETDefense(QObject):
    """Social Engineering Toolkit Defense — detects and alerts on SE attack patterns."""

    set_defense_alert = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cooldowns: dict[str, float] = {}
        self._cooldown_s = 120.0

        # DNS resolution tracking for poisoning detection
        self._dns_resolutions: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        # Beaconing detection: (src, dst) → deque of connection timestamps
        self._beacon_tracker: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=50))

        # DHCP server tracking
        self._dhcp_servers: set[str] = set()

        # ARP gateway tracking
        self._gateway_macs: dict[str, set[str]] = defaultdict(set)

        # Stats
        self._stats = {
            "phishing_detected": 0,
            "credential_leaks": 0,
            "payloads_detected": 0,
            "dns_poison_attempts": 0,
            "beaconing_sources": 0,
            "rogue_aps": 0,
        }

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def check_dns_query(self, dns_info: dict):
        """Check DNS query for phishing (typosquatting) and DNS poisoning."""
        domain = dns_info.get("query_name", dns_info.get("dns_query", ""))
        src_ip = dns_info.get("src_ip", dns_info.get("src", ""))
        response = dns_info.get("dns_response", dns_info.get("response_ips", ""))
        rcode = dns_info.get("response_code", dns_info.get("dns_rcode", ""))

        if not domain:
            return

        # ── Anti-Phishing: Typosquatting Detection ────────────
        self._check_typosquatting(domain, src_ip)

        # ── DNS Poisoning Detection ───────────────────────────
        if response and rcode != "NXDOMAIN":
            self._check_dns_poisoning(domain, response, src_ip)

    def process_packet(self, pkt_info: dict):
        """Process DPI-enriched packet for SE attack indicators."""
        app_protocol = pkt_info.get("app_protocol", "")
        src_ip = pkt_info.get("src", "")
        dst_ip = pkt_info.get("dst", "")
        dst_port = pkt_info.get("dst_port", 0)
        threat_flags = pkt_info.get("threat_flags", [])

        # ── Credential Leak Detection ─────────────────────────
        if "cleartext_auth" in threat_flags:
            self._detect_credential_leak(pkt_info)

        # ── Payload/Malware Delivery Detection ────────────────
        if app_protocol == "HTTP":
            self._check_payload_delivery(pkt_info)

        # ── DHCP Rogue AP Detection ───────────────────────────
        if app_protocol == "DHCP":
            self._check_rogue_dhcp(pkt_info)

        # ── ARP Gateway MAC tracking ─────────────────────────
        if app_protocol == "ARP":
            self._check_gateway_arp(pkt_info)

        # ── C2 Beaconing Detection ────────────────────────────
        if src_ip and dst_ip and dst_port:
            self._track_beaconing(src_ip, dst_ip, dst_port)

    def check_flows(self, flow_stats: dict):
        """Check flow statistics for SE attack patterns."""
        # Check top flows for suspicious exfiltration patterns
        for flow in flow_stats.get("top_flows", []):
            bytes_sent = flow.get("bytes_sent", 0)
            dst_ip = flow.get("dst_ip", "")
            if bytes_sent > 10 * 1024 * 1024 and dst_ip:  # >10MB outbound
                # This is informational — large transfers could be exfil
                pass

    def _check_typosquatting(self, domain: str, src_ip: str):
        """Detect typosquatting of protected domains."""
        # Strip subdomains for comparison
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain.lower()

        # Skip if it's exactly a protected domain
        if base_domain in PROTECTED_DOMAINS:
            return

        for protected in PROTECTED_DOMAINS:
            # Only compare similar-length domains
            if abs(len(base_domain) - len(protected)) > 3:
                continue
            distance = _levenshtein(base_domain, protected)
            if 0 < distance <= 2:
                self._stats["phishing_detected"] += 1
                self._emit("phishing", "warning",
                           "Phishing: Typosquatting Domain Detected",
                           f"Domain '{domain}' is similar to '{protected}' "
                           f"(edit distance: {distance})",
                           src_ip=src_ip,
                           evidence=f"Levenshtein distance: {distance} from {protected}",
                           recommended_action=f"Block domain {domain}, alert users")
                return  # Only report first match

    def _check_dns_poisoning(self, domain: str, response: str, src_ip: str):
        """Detect DNS poisoning by tracking resolution changes."""
        tracker = self._dns_resolutions[domain]
        now = time.time()

        # Parse response IPs
        response_ips = set(r.strip() for r in response.split(",") if r.strip())

        # Check if this domain has resolved to different IPs recently
        for prev_ts, prev_ips in tracker:
            if now - prev_ts < 300:  # Within 5 minutes
                if prev_ips and response_ips and prev_ips != response_ips:
                    # Different resolution — could be poisoning or CDN rotation
                    # Only alert for well-known domains
                    base = ".".join(domain.split(".")[-2:])
                    if base in PROTECTED_DOMAINS:
                        self._stats["dns_poison_attempts"] += 1
                        self._emit("dns_poison", "warning",
                                   "DNS Poisoning: Resolution Changed",
                                   f"Domain '{domain}' resolved to different IPs: "
                                   f"was {prev_ips}, now {response_ips}",
                                   src_ip=src_ip,
                                   evidence=f"Previous: {prev_ips}, Current: {response_ips}",
                                   recommended_action="Verify DNS server integrity")

        tracker.append((now, response_ips))

    def _detect_credential_leak(self, pkt_info: dict):
        """Detect cleartext credential transmission."""
        app_proto = pkt_info.get("app_protocol", "")
        src_ip = pkt_info.get("src", "")
        dst_ip = pkt_info.get("dst", "")
        dst_port = pkt_info.get("dst_port", 0)

        self._stats["credential_leaks"] += 1
        self._emit("credential_leak", "critical",
                   "Credential Leak: Cleartext Authentication",
                   f"Unencrypted {app_proto} credentials sent from {src_ip} "
                   f"to {dst_ip}:{dst_port}",
                   src_ip=src_ip, dst_ip=dst_ip,
                   evidence=f"Protocol: {app_proto}, Port: {dst_port}",
                   recommended_action=f"Switch to encrypted protocol for {app_proto}")

    def _check_payload_delivery(self, pkt_info: dict):
        """Detect malware payload delivery via HTTP."""
        threat_flags = pkt_info.get("threat_flags", [])
        payload_ascii = pkt_info.get("payload_ascii", "")
        payload_hex = pkt_info.get("payload_hex", "")
        src_ip = pkt_info.get("src", "")
        dst_ip = pkt_info.get("dst", "")

        # Check for executable downloads
        if "executable_download" in threat_flags:
            self._stats["payloads_detected"] += 1
            self._emit("payload_delivery", "critical",
                       "Payload Delivery: Executable Download",
                       f"Executable file transfer from {src_ip} to {dst_ip}",
                       src_ip=src_ip, dst_ip=dst_ip,
                       evidence="Content-Type indicates executable",
                       recommended_action="Block and quarantine file, scan for malware")
            return

        # Check for PE header (MZ magic bytes)
        if payload_hex and payload_hex[:4] == "4d5a":
            self._stats["payloads_detected"] += 1
            self._emit("payload_delivery", "critical",
                       "Payload Delivery: PE Executable Detected",
                       f"Windows executable (PE) in HTTP from {src_ip} to {dst_ip}",
                       src_ip=src_ip, dst_ip=dst_ip,
                       evidence="MZ header detected in payload",
                       recommended_action="Block transfer, quarantine endpoint")
            return

        # Check for ELF header
        if payload_hex and payload_hex[:8] == "7f454c46":
            self._stats["payloads_detected"] += 1
            self._emit("payload_delivery", "critical",
                       "Payload Delivery: ELF Binary Detected",
                       f"Linux executable (ELF) in HTTP from {src_ip} to {dst_ip}",
                       src_ip=src_ip, dst_ip=dst_ip,
                       evidence="ELF header detected in payload",
                       recommended_action="Block transfer, quarantine endpoint")
            return

        # Check for PowerShell cradles
        raw_payload = pkt_info.get("payload_raw", b"")
        if not raw_payload and payload_ascii:
            raw_payload = payload_ascii.encode("utf-8", errors="ignore")

        for pattern in POWERSHELL_PATTERNS:
            if re.search(pattern, raw_payload):
                self._stats["payloads_detected"] += 1
                self._emit("payload_delivery", "critical",
                           "Payload Delivery: PowerShell Download Cradle",
                           f"PowerShell payload pattern from {src_ip} to {dst_ip}",
                           src_ip=src_ip, dst_ip=dst_ip,
                           evidence=f"Matched pattern: {pattern.pattern.decode('utf-8', errors='ignore')[:50]}",
                           recommended_action="Block, isolate endpoint, investigate")
                return

    def _check_rogue_dhcp(self, pkt_info: dict):
        """Detect rogue DHCP servers (evil twin indicator)."""
        details = pkt_info.get("app_details", "")
        src_ip = pkt_info.get("src", "")

        if "Offer" in details or "ACK" in details:
            if src_ip and src_ip not in self._dhcp_servers:
                if self._dhcp_servers:  # Already have a known DHCP server
                    self._stats["rogue_aps"] += 1
                    self._emit("rogue_dhcp", "critical",
                               "Rogue DHCP Server Detected",
                               f"New DHCP server at {src_ip} (known: {self._dhcp_servers})",
                               src_ip=src_ip,
                               evidence=f"Known servers: {self._dhcp_servers}, New: {src_ip}",
                               recommended_action="Investigate and disable rogue DHCP server")
                self._dhcp_servers.add(src_ip)

    def _check_gateway_arp(self, pkt_info: dict):
        """Detect multiple MACs claiming to be the gateway (ARP spoofing for MITM)."""
        details = pkt_info.get("app_details", "")
        if "reply" not in details.lower():
            return

        # Extract IP and MAC from ARP details
        arp_src_ip = pkt_info.get("arp_src_ip", "")
        arp_src_mac = pkt_info.get("arp_src_mac", "")

        if arp_src_ip and arp_src_mac:
            # Track MACs per IP
            self._gateway_macs[arp_src_ip].add(arp_src_mac)
            if len(self._gateway_macs[arp_src_ip]) > 1:
                self._stats["rogue_aps"] += 1
                macs = self._gateway_macs[arp_src_ip]
                self._emit("arp_mitm", "critical",
                           "Possible MITM: Multiple MACs for Same IP",
                           f"IP {arp_src_ip} has multiple MACs: {macs}",
                           src_ip=arp_src_ip,
                           evidence=f"MACs: {', '.join(macs)}",
                           recommended_action="Verify ARP tables, check for MITM attack")

    def _track_beaconing(self, src_ip: str, dst_ip: str, dst_port: int):
        """Track connection timing for C2 beaconing detection."""
        # Only track external connections
        if dst_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            return

        key = (src_ip, dst_ip)
        tracker = self._beacon_tracker[key]
        now = time.time()
        tracker.append(now)

        # Need at least 10 samples to detect beaconing
        if len(tracker) < 10:
            return

        # Calculate intervals between connections
        intervals = [tracker[i] - tracker[i - 1] for i in range(1, len(tracker))]
        if not intervals:
            return

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 5:  # Less than 5s — too fast, probably normal traffic
            return

        # Calculate jitter (coefficient of variation)
        if mean_interval > 0:
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            std = variance ** 0.5
            cv = std / mean_interval if mean_interval > 0 else 999

            # Low jitter (CV < 0.2) = regular beaconing pattern
            if cv < 0.2 and mean_interval > 10:
                self._stats["beaconing_sources"] += 1
                self._emit("c2_beacon", "critical",
                           "C2 Beaconing: Regular Interval Connections",
                           f"{src_ip} connecting to {dst_ip}:{dst_port} "
                           f"every ~{mean_interval:.0f}s (CV={cv:.2f})",
                           src_ip=src_ip, dst_ip=dst_ip,
                           evidence=f"Interval: {mean_interval:.1f}s, Jitter CV: {cv:.3f}, "
                                    f"Samples: {len(intervals)}",
                           recommended_action=f"Block {dst_ip}, isolate {src_ip}, investigate C2")

    def _emit(self, category: str, severity: str, title: str, description: str,
              src_ip: str = "", dst_ip: str = "", evidence: str = "",
              recommended_action: str = ""):
        key = f"{category}:{src_ip}:{dst_ip}"
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self._cooldown_s:
            return
        self._cooldowns[key] = now

        event = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "rule_id": category,
            "severity": severity,
            "title": title,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "evidence": evidence,
            "recommended_action": recommended_action,
        }

        self.set_defense_alert.emit(event)

        # Also persist
        try:
            db.insert_set_defense_event(
                category=category, severity=severity, title=title,
                description=description, src_ip=src_ip, dst_ip=dst_ip,
                evidence=evidence, recommended_action=recommended_action,
            )
        except Exception:
            pass
