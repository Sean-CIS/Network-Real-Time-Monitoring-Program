"""Deep Packet Inspection engine — extracts application-layer intelligence from Scapy packets."""

import re
import struct

# Known suspicious ports
SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 1337, 9001, 12345, 54321, 65535, 8888, 9999}

# Port to protocol mapping for DPI
PORT_PROTOCOL_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 5900: "VNC",
    6379: "REDIS", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 27017: "MONGODB",
}

# DNS query type mapping
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 255: "ANY",
}

# DNS response code mapping
DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


def analyze_packet(pkt) -> dict:
    """Analyze a Scapy packet and return enriched DPI data.

    Returns dict with keys:
        app_protocol, app_details, threat_flags, payload_hex, payload_ascii,
        dns_query, dns_response, dns_qtype, dns_rcode,
        tls_sni, tls_version, http_method, http_host, http_uri,
        ssh_banner, src_port, dst_port
    """
    result = {
        "app_protocol": "",
        "app_details": "",
        "threat_flags": [],
        "payload_hex": "",
        "payload_ascii": "",
        "dns_query": "",
        "dns_response": "",
        "dns_qtype": "",
        "dns_rcode": "",
        "tls_sni": "",
        "tls_version": "",
        "http_method": "",
        "http_host": "",
        "http_uri": "",
        "ssh_banner": "",
        "src_port": 0,
        "dst_port": 0,
    }

    try:
        _analyze_layers(pkt, result)
    except Exception:
        pass

    return result


def _analyze_layers(pkt, result: dict):
    """Walk through packet layers and extract intelligence."""
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, ICMP, DHCP, Raw

    # Extract ports
    if TCP in pkt:
        result["src_port"] = pkt[TCP].sport
        result["dst_port"] = pkt[TCP].dport
    elif UDP in pkt:
        result["src_port"] = pkt[UDP].sport
        result["dst_port"] = pkt[UDP].dport

    sport = result["src_port"]
    dport = result["dst_port"]

    # Check for suspicious ports
    if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS:
        result["threat_flags"].append("suspicious_port")

    # ── ARP ───────────────────────────────────────────────────
    if ARP in pkt:
        _analyze_arp(pkt, result)
        return

    # ── ICMP ──────────────────────────────────────────────────
    if ICMP in pkt:
        _analyze_icmp(pkt, result)
        return

    # ── DHCP ──────────────────────────────────────────────────
    if DHCP in pkt:
        _analyze_dhcp(pkt, result)
        return

    # ── DNS ───────────────────────────────────────────────────
    if DNS in pkt:
        _analyze_dns(pkt, result)
        return

    # Get raw payload for protocol detection
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""

    # ── TLS/SSL ───────────────────────────────────────────────
    if payload and len(payload) > 5 and payload[0] == 0x16:
        _analyze_tls(payload, result)
        return

    # ── HTTP ──────────────────────────────────────────────────
    if payload and _is_http(payload, sport, dport):
        _analyze_http(payload, result, sport, dport)
        return

    # ── SSH ───────────────────────────────────────────────────
    if payload and (sport == 22 or dport == 22 or payload[:4] == b"SSH-"):
        _analyze_ssh(payload, result)
        return

    # ── FTP ───────────────────────────────────────────────────
    if sport == 21 or dport == 21:
        _analyze_ftp(payload, result)
        return

    # ── SMTP ──────────────────────────────────────────────────
    if dport in (25, 587, 465) or sport in (25, 587, 465):
        _analyze_smtp(payload, result)
        return

    # ── Telnet ────────────────────────────────────────────────
    if sport == 23 or dport == 23:
        result["app_protocol"] = "TELNET"
        if payload:
            result["threat_flags"].append("cleartext_auth")
            result["app_details"] = f"Telnet session ({len(payload)} bytes)"
        return

    # ── POP3 / IMAP ──────────────────────────────────────────
    if dport in (110, 143) or sport in (110, 143):
        proto = "POP3" if (dport == 110 or sport == 110) else "IMAP"
        result["app_protocol"] = proto
        if payload:
            result["threat_flags"].append("cleartext_auth")
            result["app_details"] = f"{proto} session ({len(payload)} bytes)"
        return

    # ── LDAP ──────────────────────────────────────────────────
    if dport in (389, 636) or sport in (389, 636):
        result["app_protocol"] = "LDAP" if dport == 389 or sport == 389 else "LDAPS"
        if dport == 389 and payload:
            result["threat_flags"].append("cleartext_auth")
        return

    # ── RDP ───────────────────────────────────────────────────
    if dport == 3389 or sport == 3389:
        result["app_protocol"] = "RDP"
        result["app_details"] = "Remote Desktop Protocol"
        return

    # ── SMB ───────────────────────────────────────────────────
    if dport == 445 or sport == 445:
        result["app_protocol"] = "SMB"
        result["app_details"] = "Server Message Block"
        return

    # ── NTP ───────────────────────────────────────────────────
    if dport == 123 or sport == 123:
        result["app_protocol"] = "NTP"
        return

    # ── SNMP ──────────────────────────────────────────────────
    if dport in (161, 162) or sport in (161, 162):
        result["app_protocol"] = "SNMP"
        return

    # ── Database protocols ────────────────────────────────────
    if dport in (3306, 5432, 1433, 1521, 6379, 27017):
        result["app_protocol"] = PORT_PROTOCOL_MAP.get(dport, f"DB:{dport}")
        return

    # ── Fallback: port-based classification ───────────────────
    for port in (dport, sport):
        if port in PORT_PROTOCOL_MAP:
            result["app_protocol"] = PORT_PROTOCOL_MAP[port]
            break

    # Extract payload preview
    if payload:
        result["payload_hex"] = payload[:256].hex()
        result["payload_ascii"] = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload[:256]
        )
        if len(payload) > 10000:
            result["threat_flags"].append("large_payload")


def _analyze_arp(pkt, result: dict):
    from scapy.all import ARP
    arp = pkt[ARP]
    op = "request" if arp.op == 1 else "reply" if arp.op == 2 else f"op={arp.op}"
    result["app_protocol"] = "ARP"
    result["app_details"] = (
        f"ARP {op}: {arp.psrc} ({arp.hwsrc}) → {arp.pdst} ({arp.hwdst})"
    )


def _analyze_icmp(pkt, result: dict):
    from scapy.all import ICMP
    icmp = pkt[ICMP]
    icmp_types = {
        0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
        5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
        13: "Timestamp", 14: "Timestamp Reply",
    }
    type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
    result["app_protocol"] = "ICMP"
    result["app_details"] = f"ICMP {type_name} (code={icmp.code})"

    # Check for ICMP tunnel (large payloads)
    from scapy.all import Raw
    if Raw in pkt and len(pkt[Raw].load) > 100:
        result["threat_flags"].append("icmp_large_payload")


def _analyze_dhcp(pkt, result: dict):
    from scapy.all import DHCP, BOOTP
    result["app_protocol"] = "DHCP"
    options = dict(pkt[DHCP].options) if DHCP in pkt else {}
    msg_type_map = {
        1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
        5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
    }
    msg_type = msg_type_map.get(options.get("message-type", 0), "Unknown")
    details = [f"DHCP {msg_type}"]
    if BOOTP in pkt:
        if pkt[BOOTP].yiaddr != "0.0.0.0":
            details.append(f"offered={pkt[BOOTP].yiaddr}")
    if "hostname" in options:
        details.append(f"host={options['hostname']}")
    result["app_details"] = " ".join(details)


def _analyze_dns(pkt, result: dict):
    from scapy.all import DNS, DNSQR, DNSRR
    dns = pkt[DNS]
    result["app_protocol"] = "DNS"

    # Query
    if dns.qr == 0 and DNSQR in pkt:  # Query
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        qtype_num = pkt[DNSQR].qtype
        qtype = DNS_QTYPES.get(qtype_num, str(qtype_num))
        result["dns_query"] = qname
        result["dns_qtype"] = qtype
        result["app_details"] = f"{qtype} query: {qname}"

        # Threat flags
        if len(qname) > 50:
            result["threat_flags"].append("long_dns_query")
        if qtype == "TXT":
            result["threat_flags"].append("dns_txt_query")

    # Response
    elif dns.qr == 1:
        rcode = DNS_RCODES.get(dns.rcode, f"RCODE={dns.rcode}")
        result["dns_rcode"] = rcode

        qname = ""
        if DNSQR in pkt:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            result["dns_query"] = qname

        # Collect response records
        responses = []
        if dns.ancount and DNSRR in pkt:
            rr = pkt[DNSRR]
            for _ in range(min(dns.ancount, 10)):  # limit to 10 records
                try:
                    rdata = str(rr.rdata)
                    if isinstance(rr.rdata, bytes):
                        rdata = rr.rdata.decode("utf-8", errors="ignore")
                    responses.append(rdata)
                    rr = rr.payload
                    if not hasattr(rr, "rdata"):
                        break
                except Exception:
                    break

        result["dns_response"] = ", ".join(responses[:5])
        result["app_details"] = f"DNS {rcode}: {qname} → {result['dns_response']}" if responses else f"DNS {rcode}: {qname}"

        if rcode == "NXDOMAIN":
            result["threat_flags"].append("nxdomain")


def _analyze_tls(payload: bytes, result: dict):
    result["app_protocol"] = "TLS"
    try:
        # TLS record: type(1) version(2) length(2) handshake_type(1)
        if len(payload) < 6:
            return
        content_type = payload[0]  # 0x16 = handshake
        tls_major = payload[1]
        tls_minor = payload[2]

        version_map = {
            (3, 0): "SSL 3.0", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1",
            (3, 3): "TLS 1.2", (3, 4): "TLS 1.3",
        }
        version = version_map.get((tls_major, tls_minor), f"TLS {tls_major}.{tls_minor}")
        result["tls_version"] = version

        if tls_major == 3 and tls_minor < 3:
            result["threat_flags"].append("weak_tls")

        # Parse ClientHello for SNI
        if content_type == 0x16 and len(payload) > 5:
            handshake_type = payload[5]
            if handshake_type == 0x01:  # ClientHello
                sni = _extract_sni(payload)
                if sni:
                    result["tls_sni"] = sni
                    result["app_details"] = f"TLS {version} → {sni}"
                else:
                    result["app_details"] = f"TLS {version} ClientHello"
            else:
                result["app_details"] = f"TLS {version} handshake"
        else:
            result["app_details"] = f"TLS {version} data"
    except Exception:
        result["app_details"] = "TLS (parse error)"


def _extract_sni(payload: bytes) -> str:
    """Extract Server Name Indication from TLS ClientHello."""
    try:
        # Skip: record header(5) + handshake header(4) + version(2) + random(32)
        offset = 5 + 4 + 2 + 32
        if offset >= len(payload):
            return ""

        # Session ID length
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher suites length
        if offset + 2 > len(payload):
            return ""
        cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cs_len

        # Compression methods length
        if offset >= len(payload):
            return ""
        cm_len = payload[offset]
        offset += 1 + cm_len

        # Extensions length
        if offset + 2 > len(payload):
            return ""
        ext_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2

        # Walk extensions
        ext_end = offset + ext_len
        while offset + 4 < ext_end and offset + 4 < len(payload):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                if offset + 5 < len(payload):
                    # Skip SNI list length(2) + type(1) + name length(2)
                    name_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                    if offset + 5 + name_len <= len(payload):
                        return payload[offset + 5:offset + 5 + name_len].decode("ascii", errors="ignore")
            offset += ext_data_len
    except Exception:
        pass
    return ""


def _is_http(payload: bytes, sport: int, dport: int) -> bool:
    if dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888):
        return True
    http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")
    return any(payload.startswith(m) for m in http_methods)


def _analyze_http(payload: bytes, result: dict, sport: int, dport: int):
    result["app_protocol"] = "HTTP"
    try:
        text = payload[:2048].decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return

        first_line = lines[0]

        # Request: GET /path HTTP/1.1
        req_match = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/", first_line)
        if req_match:
            method = req_match.group(1)
            uri = req_match.group(2)
            result["http_method"] = method
            result["http_uri"] = uri[:200]

            # Extract Host header
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    result["http_host"] = line.split(":", 1)[1].strip()
                    break

            result["app_details"] = f"{method} {result['http_host']}{uri[:100]}"

            # Check for credential patterns
            for line in lines:
                if "authorization: basic" in line.lower():
                    result["threat_flags"].append("cleartext_auth")
                    break

        # Response: HTTP/1.1 200 OK
        elif first_line.startswith("HTTP/"):
            resp_match = re.match(r"HTTP/\S+\s+(\d+)\s*(.*)", first_line)
            if resp_match:
                status = resp_match.group(1)
                reason = resp_match.group(2)
                result["app_details"] = f"HTTP {status} {reason}"

                # Check for executable content
                for line in lines:
                    lower_line = line.lower()
                    if "content-type:" in lower_line:
                        if any(ct in lower_line for ct in (
                            "application/x-executable", "application/x-msdos-program",
                            "application/x-msdownload", "application/octet-stream",
                        )):
                            result["threat_flags"].append("executable_download")
                        break
        else:
            result["app_details"] = f"HTTP data ({len(payload)} bytes)"

        # Payload preview
        result["payload_ascii"] = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload[:256]
        )
    except Exception:
        result["app_details"] = "HTTP (parse error)"


def _analyze_ssh(payload: bytes, result: dict):
    result["app_protocol"] = "SSH"
    try:
        text = payload[:256].decode("utf-8", errors="ignore")
        if text.startswith("SSH-"):
            banner = text.split("\r\n")[0].split("\n")[0]
            result["ssh_banner"] = banner
            result["app_details"] = f"SSH Banner: {banner}"
        else:
            result["app_details"] = f"SSH encrypted data ({len(payload)} bytes)"
    except Exception:
        result["app_details"] = "SSH session"


def _analyze_ftp(payload: bytes, result: dict):
    result["app_protocol"] = "FTP"
    if not payload:
        return
    try:
        text = payload[:256].decode("utf-8", errors="ignore").strip()
        # Detect credential commands
        upper = text.upper()
        if upper.startswith("USER ") or upper.startswith("PASS "):
            result["threat_flags"].append("cleartext_auth")
            cmd = upper.split()[0]
            result["app_details"] = f"FTP {cmd} command detected"
        elif upper.startswith("220 "):
            result["app_details"] = f"FTP Banner: {text[:100]}"
        else:
            result["app_details"] = f"FTP: {text[:80]}"
    except Exception:
        result["app_details"] = "FTP session"


def _analyze_smtp(payload: bytes, result: dict):
    result["app_protocol"] = "SMTP"
    if not payload:
        return
    try:
        text = payload[:256].decode("utf-8", errors="ignore").strip()
        upper = text.upper()
        if "AUTH PLAIN" in upper or "AUTH LOGIN" in upper:
            result["threat_flags"].append("cleartext_auth")
            result["app_details"] = "SMTP AUTH detected"
        elif upper.startswith("EHLO ") or upper.startswith("HELO "):
            result["app_details"] = f"SMTP: {text[:80]}"
        elif upper.startswith("MAIL FROM:"):
            result["app_details"] = f"SMTP: {text[:80]}"
        else:
            result["app_details"] = f"SMTP: {text[:60]}"
    except Exception:
        result["app_details"] = "SMTP session"
