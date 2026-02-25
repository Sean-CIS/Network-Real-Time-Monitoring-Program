import socket
import subprocess
import platform
import struct
from PySide6.QtCore import Signal, QThread

from src.utils import db


class DiscoveryWorker(QThread):
    """Discovers devices on the local network using ARP ping."""

    scan_complete = Signal(list)
    scan_status = Signal(str)

    def __init__(self, network: str = "192.168.1.0/24", parent=None):
        super().__init__(parent)
        self._network = network
        self._use_nmap = False

    def set_network(self, network: str):
        self._network = network

    def run(self):
        self.scan_status.emit("Scanning...")
        devices = []

        try:
            devices = self._arp_scan()
        except Exception as e:
            self.scan_status.emit(f"ARP scan failed: {e}")
            try:
                devices = self._ping_sweep()
            except Exception as e2:
                self.scan_status.emit(f"Ping sweep also failed: {e2}")

        # Enrich all discovered devices
        total = len(devices)
        for i, dev in enumerate(devices):
            self.scan_status.emit(f"Enriching device {i + 1}/{total}: {dev['ip']}")

            # Resolve hostname (multi-method)
            if not dev.get("hostname"):
                dev["hostname"] = self._resolve_hostname(dev["ip"])

            # MAC vendor lookup
            if dev.get("mac") and not dev.get("vendor"):
                dev["vendor"] = self._lookup_mac_vendor(dev["mac"])

            # OS fingerprint via TTL
            if not dev.get("os_info"):
                dev["os_info"] = self._detect_os_by_ttl(dev["ip"])

            # Persist to database
            db.upsert_device(
                ip=dev["ip"],
                mac=dev.get("mac", ""),
                hostname=dev.get("hostname", ""),
                os_info=dev.get("os_info", ""),
                vendor=dev.get("vendor", ""),
            )

        status = f"Scan complete: {len(devices)} device(s) found"
        self.scan_status.emit(status)
        self.scan_complete.emit(devices)

    def _arp_scan(self) -> list[dict]:
        """Use scapy for ARP-based device discovery."""
        try:
            from scapy.all import ARP, Ether, srp

            arp_request = ARP(pdst=self._network)
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

    def _ping_sweep(self) -> list[dict]:
        """Fallback: TCP connect scan when scapy/raw sockets unavailable."""
        import ipaddress
        import shutil

        network = ipaddress.ip_network(self._network, strict=False)
        devices = []

        # Try icmplib first (pure Python ICMP, no ping binary needed)
        try:
            from icmplib import multiping
            hosts = [str(h) for h in network.hosts()]
            self.scan_status.emit(f"ICMP scanning {len(hosts)} hosts...")
            results = multiping(hosts, count=1, timeout=1, privileged=False)
            for result in results:
                if result.is_alive:
                    devices.append({
                        "ip": result.address,
                        "mac": "",
                        "hostname": "",
                        "vendor": "",
                        "os_info": "",
                        "is_online": True,
                    })
            return devices
        except ImportError:
            pass
        except Exception:
            pass

        # Try system ping if available
        if shutil.which("ping"):
            is_windows = platform.system().lower() == "windows"
            count_flag = "-n" if is_windows else "-c"
            # Windows: -w timeout in ms; Linux: -W timeout in seconds
            timeout_flag = "-w" if is_windows else "-W"
            timeout_val = "500" if is_windows else "1"
            for host in network.hosts():
                host_str = str(host)
                self.scan_status.emit(f"Pinging {host_str}...")
                try:
                    result = subprocess.run(
                        ["ping", count_flag, "1", timeout_flag, timeout_val, host_str],
                        capture_output=True, text=True, timeout=3,
                    )
                    if result.returncode == 0:
                        devices.append({
                            "ip": host_str,
                            "mac": "",
                            "hostname": "",
                            "vendor": "",
                            "os_info": "",
                            "is_online": True,
                        })
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    continue
            return devices

        # Last resort: TCP connect probe on common ports
        self.scan_status.emit("No ping available, using TCP connect scan...")
        common_ports = [22, 80, 443, 445, 8080, 3389]
        for host in network.hosts():
            host_str = str(host)
            self.scan_status.emit(f"TCP probing {host_str}...")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    if sock.connect_ex((host_str, port)) == 0:
                        devices.append({
                            "ip": host_str,
                            "mac": "",
                            "hostname": "",
                            "vendor": "",
                            "os_info": "",
                            "is_online": True,
                        })
                        sock.close()
                        break  # Found one open port, device is alive
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
        """Multi-method hostname resolution: DNS, mDNS, NetBIOS."""
        # Method 1: Standard reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                return hostname
        except (socket.herror, socket.gaierror, OSError):
            pass

        # Method 2: mDNS via zeroconf
        try:
            from zeroconf import Zeroconf, ServiceBrowser
            import time
            zc = Zeroconf()
            # Try to find the hostname by querying the .local domain
            # This is a simplified approach
            try:
                from zeroconf import IPVersion
                info = zc.get_service_info("_http._tcp.local.", f"_{ip}._tcp.local.", timeout=1000)
                if info and info.server:
                    zc.close()
                    return info.server.rstrip(".")
            except Exception:
                pass
            zc.close()
        except ImportError:
            pass

        # Method 3: NetBIOS name query (port 137) for Windows hosts
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
                "AABBCC": "Apple",
                "001A2B": "Apple",
                "3C5AB4": "Google",
                "B47C9C": "Amazon",
                "001E58": "D-Link",
                "000C29": "VMware",
                "005056": "VMware",
                "080027": "VirtualBox",
                "525400": "QEMU/KVM",
                "F8FF0A": "Apple",
            }
            return COMMON_OUIS.get(oui, "")

    @staticmethod
    def _detect_os_by_ttl(ip: str) -> str:
        """Detect OS by analyzing ping TTL value."""
        import shutil

        # Try icmplib first (no ping binary needed)
        try:
            from icmplib import ping as icmp_ping
            result = icmp_ping(ip, count=1, timeout=1, privileged=False)
            if result.is_alive and result.rtts:
                # icmplib doesn't expose TTL directly in unprivileged mode
                # but we can try via raw response if available
                pass
        except (ImportError, Exception):
            pass

        # Try system ping if available
        if shutil.which("ping"):
            param = "-n" if platform.system().lower() == "windows" else "-c"
            try:
                result = subprocess.run(
                    ["ping", param, "1", "-W", "1", ip],
                    capture_output=True, text=True, timeout=3,
                )
                output = result.stdout.lower()
                import re
                ttl_match = re.search(r"ttl[=:](\d+)", output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        if ttl > 48:
                            return "Linux/macOS"
                        else:
                            return "Linux (routed)"
                    elif ttl <= 128:
                        if ttl > 112:
                            return "Windows"
                        else:
                            return "Windows (routed)"
                    elif ttl <= 255:
                        return "Network Equipment"
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
                pass

        # Try TCP connect fingerprinting as fallback
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # If port 22 is open, likely Linux/server
            if sock.connect_ex((ip, 22)) == 0:
                sock.close()
                return "Linux/Unix (SSH)"
            sock.close()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # If port 3389 is open, likely Windows
            if sock.connect_ex((ip, 3389)) == 0:
                sock.close()
                return "Windows (RDP)"
            sock.close()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # If port 445 is open, likely Windows
            if sock.connect_ex((ip, 445)) == 0:
                sock.close()
                return "Windows (SMB)"
            sock.close()
        except (OSError, socket.timeout):
            pass

        return ""


def _netbios_query(ip: str, timeout: float = 1.0) -> str:
    """Send a NetBIOS Name Service query to resolve hostname."""
    try:
        # NetBIOS name query packet
        transaction_id = b'\x00\x01'
        flags = b'\x00\x00'
        questions = b'\x00\x01'
        answer_rrs = b'\x00\x00'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        # Wildcard name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
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
