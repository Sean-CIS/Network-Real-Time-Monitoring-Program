"""DNS Intelligence Monitor — tracks all DNS activity and detects anomalies."""

import math
import time
from collections import defaultdict, deque
from datetime import datetime

from PySide6.QtCore import QObject, Signal, QTimer

from src.utils import db


class DNSMonitor(QObject):
    """Monitors DNS queries/responses for intelligence and anomaly detection."""

    dns_stats_updated = Signal(dict)
    dns_query_logged = Signal(dict)

    # Suspicious TLDs commonly abused
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".cc", ".su", ".bit", ".onion"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._queries: deque = deque(maxlen=10000)
        self._domain_counts: dict[str, int] = defaultdict(int)
        self._source_queries: dict[str, deque] = defaultdict(lambda: deque())
        self._source_nx: dict[str, int] = defaultdict(int)
        self._source_total: dict[str, int] = defaultdict(int)
        self._unique_domains_per_source: dict[str, set] = defaultdict(set)
        self._query_types: dict[str, int] = defaultdict(int)
        self._total_queries = 0
        self._total_nx = 0
        self._total_suspicious = 0

        # Stats emission timer
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(2000)
        self._stats_timer.timeout.connect(self._emit_stats)
        self._stats_timer.start()

    def process_dns(self, dns_info: dict):
        """Process a DNS packet from the DPI engine."""
        query = dns_info.get("dns_query", "")
        if not query:
            return

        src_ip = dns_info.get("src", "")
        qtype = dns_info.get("dns_qtype", "A")
        rcode = dns_info.get("dns_rcode", "")
        response = dns_info.get("dns_response", "")
        now = time.time()

        self._total_queries += 1
        self._domain_counts[query] += 1
        self._query_types[qtype] += 1

        if src_ip:
            self._source_queries[src_ip].append(now)
            self._source_total[src_ip] += 1
            self._unique_domains_per_source[src_ip].add(query)
            # Prune old entries
            tracker = self._source_queries[src_ip]
            while tracker and now - tracker[0] > 60:
                tracker.popleft()

        # Check for NXDOMAIN
        is_nx = rcode == "NXDOMAIN"
        if is_nx:
            self._total_nx += 1
            if src_ip:
                self._source_nx[src_ip] += 1

        # Anomaly detection
        is_suspicious = self._check_suspicious(query, qtype, src_ip, is_nx)
        if is_suspicious:
            self._total_suspicious += 1

        # Build log entry
        entry = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "query_name": query,
            "query_type": qtype,
            "response_ips": response,
            "response_code": rcode or "NOERROR",
            "is_suspicious": is_suspicious,
        }

        self._queries.append(entry)
        self.dns_query_logged.emit(entry)

        # Persist to DB (batch every 10th query to reduce I/O)
        if self._total_queries % 10 == 0:
            try:
                db.insert_dns_log(
                    src_ip=src_ip, query_name=query, query_type=qtype,
                    response_ips=response, response_code=rcode or "NOERROR",
                    is_suspicious=is_suspicious,
                )
            except Exception:
                pass

    def _check_suspicious(self, query: str, qtype: str, src_ip: str, is_nx: bool) -> bool:
        """Check if a DNS query is suspicious."""
        flags = []

        # Long domain name (possible tunneling)
        if len(query) > 40:
            flags.append("long_domain")

        # High entropy subdomain (possible DGA)
        parts = query.split(".")
        if len(parts) > 2:
            subdomain = parts[0]
            if len(subdomain) > 10:
                entropy = self._shannon_entropy(subdomain)
                if entropy > 3.5:
                    flags.append("high_entropy")

        # Suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if query.endswith(tld):
                flags.append("suspicious_tld")
                break

        # TXT record (possible tunneling)
        if qtype == "TXT":
            flags.append("txt_query")

        # NXDOMAIN (possible DGA)
        if is_nx:
            flags.append("nxdomain")

        # High NX rate from source (>30%)
        if src_ip and self._source_total.get(src_ip, 0) > 20:
            nx_rate = self._source_nx.get(src_ip, 0) / self._source_total[src_ip]
            if nx_rate > 0.3:
                flags.append("high_nx_rate")

        # Rapid unique domain generation (>50/min from single source)
        if src_ip and len(self._unique_domains_per_source.get(src_ip, set())) > 50:
            flags.append("rapid_domains")

        return len(flags) > 0

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _emit_stats(self):
        """Emit aggregated DNS statistics."""
        # Top domains
        top_domains = sorted(self._domain_counts.items(), key=lambda x: x[1], reverse=True)[:30]

        # Query rate (queries in last 60s)
        now = time.time()
        recent = sum(1 for q in self._queries if now - time.mktime(
            datetime.fromisoformat(q["timestamp"]).timetuple()) < 60)
        query_rate = recent / 60.0 if recent > 0 else 0

        stats = {
            "total_queries": self._total_queries,
            "unique_domains": len(self._domain_counts),
            "nx_domains": self._total_nx,
            "suspicious": self._total_suspicious,
            "query_rate": query_rate,
            "query_types": dict(self._query_types),
            "top_domains": top_domains,
        }
        self.dns_stats_updated.emit(stats)
