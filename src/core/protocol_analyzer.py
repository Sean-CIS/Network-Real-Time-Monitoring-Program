"""Deep packet inspection for application-layer protocol analysis."""

import struct


class ProtocolAnalyzer:
    """Inspects raw packets for application-layer protocol details."""

    # Protocol distribution counters
    def __init__(self):
        self._protocol_counts: dict[str, int] = {}

    @property
    def protocol_counts(self) -> dict[str, int]:
        return dict(self._protocol_counts)

    def reset(self):
        self._protocol_counts.clear()

    def _count(self, proto: str):
        self._protocol_counts[proto] = self._protocol_counts.get(proto, 0) + 1

    def analyze(self, raw_pkt) -> dict:
        """Analyze a raw scapy packet and return protocol details.

        Returns dict with optional keys:
            app_protocol: str  — e.g. "HTTP", "DNS", "TLS", "DHCP", etc.
            detail: str        — human-readable detail string
            sni: str           — TLS Server Name Indication (if ClientHello)
            tls_version: str   — TLS version string
            http_method: str   — HTTP method
            http_host: str     — HTTP Host header
            dns_query: str     — DNS query name
            dns_type: str      — DNS query type
            dns_response: str  — DNS response summary
        """
        result: dict = {}

        try:
            from scapy.all import IP, TCP, UDP, ARP, ICMP, DNS, DNSQR, DNSRR, DHCP, Raw
        except ImportError:
            return result

        # ARP
        if ARP in raw_pkt:
            result.update(self._analyze_arp(raw_pkt[ARP]))
            return result

        if IP not in raw_pkt:
            return result

        # ICMP
        if ICMP in raw_pkt:
            result.update(self._analyze_icmp(raw_pkt[ICMP]))
            return result

        # TCP-based protocols
        if TCP in raw_pkt:
            tcp = raw_pkt[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b""

            # DNS over TCP (port 53)
            if DNS in raw_pkt:
                result.update(self._analyze_dns(raw_pkt[DNS]))
                return result

            # TLS (port 443 or other)
            if payload and len(payload) > 5:
                tls_result = self._analyze_tls(payload)
                if tls_result:
                    result.update(tls_result)
                    return result

            # HTTP (check for HTTP methods in payload)
            if payload:
                http_result = self._analyze_http(payload)
                if http_result:
                    result.update(http_result)
                    return result

            self._count("TCP (other)")

        # UDP-based protocols
        elif UDP in raw_pkt:
            udp = raw_pkt[UDP]

            # DNS
            if DNS in raw_pkt:
                result.update(self._analyze_dns(raw_pkt[DNS]))
                return result

            # DHCP
            if DHCP in raw_pkt:
                result.update(self._analyze_dhcp(raw_pkt[DHCP]))
                return result

            # QUIC (UDP port 443)
            if udp.dport == 443 or udp.sport == 443:
                payload = bytes(udp.payload) if udp.payload else b""
                # Try TLS/QUIC Initial packet SNI extraction
                if payload and len(payload) > 5:
                    tls_result = self._analyze_quic_initial(payload)
                    if tls_result:
                        result.update(tls_result)
                        return result
                self._count("QUIC")
                result["app_protocol"] = "QUIC"
                result["detail"] = f"QUIC :{udp.sport} -> :{udp.dport}"
                return result

            self._count("UDP (other)")

        return result

    def _analyze_http(self, payload: bytes) -> dict | None:
        """Parse HTTP request/response from TCP payload."""
        try:
            text = payload[:2048].decode("utf-8", errors="ignore")
        except Exception:
            return None

        methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
                   "PATCH ", "CONNECT ")
        for method in methods:
            if text.startswith(method):
                self._count("HTTP")
                lines = text.split("\r\n")
                request_line = lines[0] if lines else ""
                host = ""
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                result = {
                    "app_protocol": "HTTP",
                    "detail": request_line[:120],
                    "http_method": method.strip(),
                }
                if host:
                    result["http_host"] = host
                return result

        if text.startswith("HTTP/"):
            self._count("HTTP")
            status_line = text.split("\r\n")[0] if "\r\n" in text else text[:80]
            return {
                "app_protocol": "HTTP",
                "detail": status_line[:120],
            }

        return None

    def _analyze_dns(self, dns_layer) -> dict:
        """Parse DNS query and response details."""
        self._count("DNS")
        result: dict = {"app_protocol": "DNS"}

        qname = ""
        qtype = ""
        if dns_layer.qd and hasattr(dns_layer.qd, "qname"):
            try:
                qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            except (AttributeError, UnicodeDecodeError):
                pass
            qtype_num = getattr(dns_layer.qd, "qtype", 0)
            qtype = _DNS_TYPES.get(qtype_num, str(qtype_num))

        if qname:
            result["dns_query"] = qname
            result["dns_type"] = qtype

        # Check if it's a response (QR=1)
        if dns_layer.qr == 1:
            answers = []
            for i in range(dns_layer.ancount or 0):
                try:
                    rr = dns_layer.an[i] if hasattr(dns_layer, "an") else None
                    if rr and hasattr(rr, "rdata"):
                        rdata = str(rr.rdata)
                        if isinstance(rr.rdata, bytes):
                            rdata = rr.rdata.decode("utf-8", errors="ignore")
                        answers.append(rdata)
                except (IndexError, AttributeError):
                    break
                if len(answers) >= 3:
                    break

            rcode = dns_layer.rcode if hasattr(dns_layer, "rcode") else 0
            rcode_str = _DNS_RCODES.get(rcode, str(rcode))

            if answers:
                result["dns_response"] = ", ".join(answers[:3])
                result["detail"] = f"DNS {qtype} {qname} -> {', '.join(answers[:2])} [{rcode_str}]"
            else:
                result["detail"] = f"DNS {qtype} {qname} [{rcode_str}]"
        else:
            result["detail"] = f"DNS {qtype} {qname}"

        return result

    def _analyze_tls(self, payload: bytes) -> dict | None:
        """Parse TLS record and extract SNI from ClientHello."""
        if len(payload) < 6:
            return None

        content_type = payload[0]
        if content_type != 22:  # Handshake
            if content_type == 23:  # Application Data
                self._count("TLS")
                tls_ver = self._tls_version_str(payload[1], payload[2])
                return {
                    "app_protocol": "TLS",
                    "detail": f"TLS {tls_ver} Application Data",
                    "tls_version": tls_ver,
                }
            return None

        # TLS Handshake
        if len(payload) < 6:
            return None

        tls_ver = self._tls_version_str(payload[1], payload[2])
        # record_length = struct.unpack("!H", payload[3:5])[0]
        handshake_type = payload[5]

        if handshake_type == 1:  # ClientHello
            sni = self._extract_sni(payload[5:])
            self._count("TLS")
            result = {
                "app_protocol": "TLS",
                "tls_version": tls_ver,
            }
            if sni:
                result["sni"] = sni
                result["detail"] = f"TLS {tls_ver} ClientHello SNI={sni}"
            else:
                result["detail"] = f"TLS {tls_ver} ClientHello"
            return result
        elif handshake_type == 2:  # ServerHello
            self._count("TLS")
            return {
                "app_protocol": "TLS",
                "detail": f"TLS {tls_ver} ServerHello",
                "tls_version": tls_ver,
            }

        self._count("TLS")
        return {
            "app_protocol": "TLS",
            "detail": f"TLS {tls_ver} Handshake",
            "tls_version": tls_ver,
        }

    def _extract_sni(self, handshake: bytes) -> str:
        """Extract SNI from a TLS ClientHello handshake message."""
        try:
            if len(handshake) < 42:
                return ""

            # Skip: handshake_type(1) + length(3) + version(2) + random(32)
            offset = 38
            # Session ID
            if offset >= len(handshake):
                return ""
            session_id_len = handshake[offset]
            offset += 1 + session_id_len

            # Cipher suites
            if offset + 2 > len(handshake):
                return ""
            cipher_suites_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len

            # Compression methods
            if offset >= len(handshake):
                return ""
            comp_methods_len = handshake[offset]
            offset += 1 + comp_methods_len

            # Extensions
            if offset + 2 > len(handshake):
                return ""
            extensions_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
            offset += 2

            end = offset + extensions_len
            while offset + 4 <= end and offset + 4 <= len(handshake):
                ext_type = struct.unpack("!H", handshake[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", handshake[offset + 2:offset + 4])[0]
                offset += 4

                if ext_type == 0:  # SNI extension
                    if offset + 5 <= len(handshake):
                        # Skip SNI list length (2 bytes)
                        # SNI type (1 byte, should be 0 for hostname)
                        sni_type = handshake[offset + 2]
                        if sni_type == 0:
                            name_len = struct.unpack(
                                "!H", handshake[offset + 3:offset + 5]
                            )[0]
                            if offset + 5 + name_len <= len(handshake):
                                return handshake[offset + 5:offset + 5 + name_len].decode(
                                    "ascii", errors="ignore"
                                )
                    return ""

                offset += ext_len
        except (struct.error, IndexError, ValueError):
            pass
        return ""

    def _analyze_quic_initial(self, payload: bytes) -> dict | None:
        """Try to extract SNI from QUIC Initial packet."""
        # QUIC Initial packets have a specific format
        # The first byte has form 1XPPPPPP where PP is packet type
        if len(payload) < 5:
            return None
        first_byte = payload[0]
        if not (first_byte & 0x80):  # Must be long header
            return None

        # Try to find TLS ClientHello within QUIC payload
        # This is simplified — real QUIC parsing would need crypto
        # Search for TLS ClientHello pattern in the payload
        for i in range(4, min(len(payload) - 6, 1200)):
            if payload[i] == 0x16 and payload[i + 1] == 0x03:
                tls_result = self._analyze_tls(payload[i:])
                if tls_result and tls_result.get("sni"):
                    tls_result["app_protocol"] = "QUIC"
                    tls_result["detail"] = (
                        f"QUIC Initial SNI={tls_result['sni']}"
                    )
                    self._count("QUIC")
                    return tls_result
        return None

    def _analyze_dhcp(self, dhcp_layer) -> dict:
        """Parse DHCP message details."""
        self._count("DHCP")
        msg_type = ""
        for option in dhcp_layer.options:
            if isinstance(option, tuple) and option[0] == "message-type":
                msg_type = _DHCP_TYPES.get(option[1], str(option[1]))
                break
        return {
            "app_protocol": "DHCP",
            "detail": f"DHCP {msg_type}" if msg_type else "DHCP",
        }

    def _analyze_arp(self, arp_layer) -> dict:
        """Parse ARP operation details."""
        self._count("ARP")
        op = "Request" if arp_layer.op == 1 else "Reply" if arp_layer.op == 2 else f"op={arp_layer.op}"
        psrc = getattr(arp_layer, "psrc", "?")
        pdst = getattr(arp_layer, "pdst", "?")
        hwsrc = getattr(arp_layer, "hwsrc", "?")
        return {
            "app_protocol": "ARP",
            "detail": f"ARP {op}: {psrc} ({hwsrc}) -> {pdst}",
        }

    def _analyze_icmp(self, icmp_layer) -> dict:
        """Parse ICMP type and code."""
        self._count("ICMP")
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        desc = _ICMP_TYPES.get((icmp_type, icmp_code),
                               _ICMP_TYPES.get((icmp_type, None), f"type={icmp_type} code={icmp_code}"))
        return {
            "app_protocol": "ICMP",
            "detail": f"ICMP {desc}",
        }

    @staticmethod
    def _tls_version_str(major: int, minor: int) -> str:
        versions = {
            (3, 0): "SSL 3.0",
            (3, 1): "1.0",
            (3, 2): "1.1",
            (3, 3): "1.2/1.3",
            (3, 4): "1.3",
        }
        return versions.get((major, minor), f"{major}.{minor}")


# Lookup tables
_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY", 257: "CAA",
}

_DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

_DHCP_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
    5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
}

_ICMP_TYPES = {
    (0, 0): "Echo Reply",
    (3, 0): "Network Unreachable",
    (3, 1): "Host Unreachable",
    (3, 3): "Port Unreachable",
    (3, None): "Destination Unreachable",
    (8, 0): "Echo Request",
    (11, 0): "TTL Exceeded",
    (11, None): "Time Exceeded",
}
