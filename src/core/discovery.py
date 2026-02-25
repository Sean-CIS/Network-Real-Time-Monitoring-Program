"""Network Device Discovery — ARP, ICMP, TCP, with auto-detection and Windows support."""

import ipaddress
import socket
import subprocess
import platform
import re
import struct
import threading
from collections import defaultdict

from PySide6.QtCore import Signal, QThread

from src.utils import db

_IS_WINDOWS = platform.system().lower() == "windows"


class DiscoveryWorker(QThread):
    """Discovers devices on the local network using ARP ping with multi-method fallback."""

    scan_complete = Signal(list)
    scan_status = Signal(str)

    def __init__(self, network: str = "auto", parent=None):
        super().__init__(parent)
        self._network = network
        self._error_counts: dict[str, int] = defaultdict(int)

    def set_network(self, network: str):
        # Validate CIDR if not "auto"
        if network != "auto":
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                self.scan_status.emit(f"Invalid network CIDR '{network}': {e}")
                return
        self._network = network

    def run(self):
        self.scan_status.emit("Scanning...")

        # Auto-detect network if set to "auto"
        network = self._network
        if network == "auto":
            network = self._auto_detect_network()
            if not network:
                self.scan_status.emit("Could not detect local network — set network manually in config.yaml")
                self.scan_complete.emit([])
                return
            self.scan_status.emit(f"Auto-detected network: {network}")

        devices = []

        # Try ARP scan first (requires admin + Npcap on Windows)
        try:
            devices = self._arp_scan(network)
        except Exception as e:
            reason = str(e)
            if "npcap" in reason.lower() or "winpcap" in reason.lower() or "libpcap" in reason.lower():
                self.scan_status.emit("ARP scan requires Npcap on Windows — using fallback methods")
            else:
                self.scan_status.emit(f"ARP scan failed: {e} — using fallback")
            try:
                devices = self._ping_sweep(network)
            except Exception as e2:
                self.scan_status.emit(f"Ping sweep also failed: {e2}")

        # Enrich all discovered devices
        total = len(devices)
        for i, dev in enumerate(devices):
            self.scan_status.emit(f"Enriching device {i + 1}/{total}: {dev['ip']}")

            # Resolve hostname (multi-method, with timeout)
            if not dev.get("hostname"):
                dev["hostname"] = self._resolve_hostname(dev["ip"])

            # MAC vendor lookup
            if dev.get("mac") and not dev.get("vendor"):
                dev["vendor"] = self._lookup_mac_vendor(dev["mac"])

            # OS fingerprint via TTL
            if not dev.get("os_info"):
                dev["os_info"] = self._detect_os_by_ttl(dev["ip"])

            # Persist to database
            try:
                db.upsert_device(
                    ip=dev["ip"],
                    mac=dev.get("mac", ""),
                    hostname=dev.get("hostname", ""),
                    os_info=dev.get("os_info", ""),
                    vendor=dev.get("vendor", ""),
                )
            except Exception as e:
                self._log_error("db_upsert", e)

        status = f"Scan complete: {len(devices)} device(s) found"
        self.scan_status.emit(status)
        self.scan_complete.emit(devices)

    @staticmethod
    def _auto_detect_network() -> str:
        """Auto-detect the local network CIDR using psutil or platform tools."""
        # Method 1: psutil (cross-platform)
        try:
            import psutil
            gateways = None
            # Try netifaces-style gateway detection
            try:
                import netifaces
                gws = netifaces.gateways()
                default_gw = gws.get("default", {}).get(netifaces.AF_INET)
                if default_gw:
                    iface_name = default_gw[1]
            except ImportError:
                iface_name = None

            # Find the best interface with a real IP
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ip = addr.address
                        netmask = addr.netmask
                        if ip and netmask:
                            try:
                                net = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                                # Skip very large networks (probably VPN/docker)
                                if net.prefixlen >= 16:
                                    return str(net)
                            except ValueError:
                                continue
        except ImportError:
            pass

        # Method 2: Platform-specific commands
        if _IS_WINDOWS:
            try:
                result = subprocess.run(
                    ["ipconfig"], capture_output=True, text=True, timeout=5
                )
                # Parse IPv4 Address and Subnet Mask
                ip_match = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", result.stdout)
                mask_match = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", result.stdout)
                if ip_match and mask_match:
                    ip = ip_match.group(1)
                    mask = mask_match.group(1)
                    if not ip.startswith("127."):
                        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                        return str(net)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        else:
            try:
                result = subprocess.run(
                    ["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=5
                )
                for match in re.finditer(r"inet ([\d.]+/\d+)", result.stdout):
                    cidr = match.group(1)
                    if not cidr.startswith("127."):
                        net = ipaddress.ip_network(cidr, strict=False)
                        if net.prefixlen >= 16:
                            return str(net)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

        # Fallback
        return "192.168.1.0/24"

    @staticmethod
    def _arp_scan(network: str) -> list[dict]:
        """Use scapy for ARP-based device discovery."""
        try:
            from scapy.all import ARP, Ether, srp

            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=3, verbose=False)
            devices = []
            for sent, received in answered:
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": "",
                    "vendor": "",
                    "os_info": "",
                    "is_online": True,
                })
            return devices
        except ImportError:
            raise RuntimeError("scapy not installed")

    @staticmethod
    def _ping_sweep(network: str) -> list[dict]:
        """Fallback: ICMP/ping/TCP scan when scapy/raw sockets unavailable."""
        import shutil

        net = ipaddress.ip_network(network, strict=False)
        devices = []

        # Try icmplib first (pure Python ICMP, no ping binary needed)
        try:
            from icmplib import multiping
            hosts = [str(h) for h in net.hosts()]
            results = multiping(hosts, count=1, timeout=1, privileged=False)
            for result in results:
                if result.is_alive:
                    devices.append({
                        "ip": result.address,
                        "mac": "", "hostname": "", "vendor": "",
                        "os_info": "", "is_online": True,
                    })
            if devices:
                return devices
        except ImportError:
            pass
        except Exception:
            pass  # Fall through to next method

        # Try system ping
        if shutil.which("ping"):
            count_flag = "-n" if _IS_WINDOWS else "-c"
            timeout_flag = "-w" if _IS_WINDOWS else "-W"
            timeout_val = "500" if _IS_WINDOWS else "1"
            for host in net.hosts():
                host_str = str(host)
                try:
                    result = subprocess.run(
                        ["ping", count_flag, "1", timeout_flag, timeout_val, host_str],
                        capture_output=True, text=True, timeout=3,
                    )
                    if result.returncode == 0:
                        devices.append({
                            "ip": host_str,
                            "mac": "", "hostname": "", "vendor": "",
                            "os_info": "", "is_online": True,
                        })
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    continue
            if devices:
                return devices

        # Last resort: TCP connect probe on common ports
        common_ports = [22, 80, 443, 445, 8080, 3389, 139, 5353, 53]
        for host in net.hosts():
            host_str = str(host)
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    if sock.connect_ex((host_str, port)) == 0:
                        devices.append({
                            "ip": host_str,
                            "mac": "", "hostname": "", "vendor": "",
                            "os_info": "", "is_online": True,
                        })
                        sock.close()
                        break
                    sock.close()
                except (OSError, socket.timeout):
                    try:
                        sock.close()
                    except Exception:
                        pass
                    continue

        return devices

    # ── Enrichment Methods ────────────────────────────────────

    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        """Multi-method hostname resolution with timeout protection."""
        # Method 1: Standard reverse DNS (with thread timeout)
        result = [None]

        def _dns_lookup():
            try:
                result[0] = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                pass

        t = threading.Thread(target=_dns_lookup, daemon=True)
        t.start()
        t.join(timeout=2.0)
        if result[0]:
            return result[0]

        # Method 2: NetBIOS name query (port 137) — works well for Windows hosts
        try:
            hostname = _netbios_query(ip)
            if hostname:
                return hostname
        except Exception:
            pass

        return ""

    @staticmethod
    def _lookup_mac_vendor(mac: str) -> str:
        """Lookup MAC address vendor using OUI database."""
        try:
            from mac_vendor_lookup import MacLookup
            lookup = MacLookup()
            vendor = lookup.lookup(mac)
            return vendor if vendor else ""
        except Exception:
            # Fallback: manual OUI prefix check for common vendors
            oui = mac.upper().replace(":", "").replace("-", "")[:6]
            COMMON_OUIS = {
                "AABBCC": "Apple", "001A2B": "Apple", "3C5AB4": "Google",
                "B47C9C": "Amazon", "001E58": "D-Link", "000C29": "VMware",
                "005056": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM",
                "F8FF0A": "Apple",
            }
            return COMMON_OUIS.get(oui, "")

    @staticmethod
    def _detect_os_by_ttl(ip: str) -> str:
        """Detect OS by analyzing ping TTL value."""
        import shutil

        # Try system ping with correct platform flags
        if shutil.which("ping"):
            count_flag = "-n" if _IS_WINDOWS else "-c"
            timeout_flag = "-w" if _IS_WINDOWS else "-W"
            timeout_val = "500" if _IS_WINDOWS else "1"
            try:
                result = subprocess.run(
                    ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
                    capture_output=True, text=True, timeout=3,
                )
                output = result.stdout.lower()
                ttl_match = re.search(r"ttl[=:](\d+)", output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        return "Linux/macOS" if ttl > 48 else "Linux (routed)"
                    elif ttl <= 128:
                        return "Windows" if ttl > 112 else "Windows (routed)"
                    elif ttl <= 255:
                        return "Network Equipment"
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
                pass

        # Try TCP connect fingerprinting as fallback
        port_os_map = [(22, "Linux/Unix (SSH)"), (3389, "Windows (RDP)"),
                       (445, "Windows (SMB)"), (548, "macOS (AFP)")]
        for port, os_label in port_os_map:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    sock.close()
                    return os_label
                sock.close()
            except (OSError, socket.timeout):
                try:
                    sock.close()
                except Exception:
                    pass

        return ""

    def _log_error(self, category: str, e: Exception):
        self._error_counts[category] += 1
        count = self._error_counts[category]
        if count == 1 or count % 50 == 0:
            self.scan_status.emit(f"Error [{category}]: {e} (occurred {count}x)")


def _netbios_query(ip: str, timeout: float = 1.0) -> str:
    """Send a NetBIOS Name Service query to resolve hostname."""
    try:
        transaction_id = b'\x00\x01'
        flags = b'\x00\x00'
        questions = b'\x00\x01'
        answer_rrs = b'\x00\x00'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        name = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
        query_type = b'\x00\x21'  # NBSTAT
        query_class = b'\x00\x01'  # IN

        packet = (transaction_id + flags + questions + answer_rrs +
                  authority_rrs + additional_rrs + name + query_type + query_class)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 57:
            num_names = data[56]
            if num_names > 0:
                name_bytes = data[57:57 + 15]
                hostname = name_bytes.decode("ascii", errors="ignore").strip()
                if hostname:
                    return hostname
    except Exception:
        pass
    return ""
