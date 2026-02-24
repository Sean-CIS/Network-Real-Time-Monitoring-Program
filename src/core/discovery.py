import socket
import subprocess
import platform
from PySide6.QtCore import Signal, QThread

from src.utils import db


class DiscoveryWorker(QThread):
    """Discovers devices on the local network using ARP ping."""

    scan_complete = Signal(list)
    scan_status = Signal(str)

    def __init__(self, network: str = "192.168.1.0/24", local_ip: str = "",
                 parent=None):
        super().__init__(parent)
        self._network = network
        self._local_ip = local_ip
        self._use_nmap = False

    def set_network(self, network: str):
        self._network = network

    def set_local_ip(self, local_ip: str):
        self._local_ip = local_ip

    def run(self):
        self.scan_status.emit(f"Scanning {self._network}...")
        devices = []

        try:
            devices = self._arp_scan()
        except Exception as e:
            self.scan_status.emit(
                f"ARP scan failed ({e}) — trying ping sweep. "
                "Run as administrator for best results."
            )
            try:
                devices = self._ping_sweep()
            except Exception as e2:
                self.scan_status.emit(
                    f"Scan failed: {e2}. Try running as administrator for ARP scanning."
                )

        # Ensure the local machine is always included
        self._ensure_local_device(devices)

        # Resolve hostnames
        for dev in devices:
            if not dev.get("hostname"):
                try:
                    hostname = socket.gethostbyaddr(dev["ip"])[0]
                    dev["hostname"] = hostname
                except (socket.herror, socket.gaierror, OSError):
                    dev["hostname"] = ""

            # Persist to database
            db.upsert_device(
                ip=dev["ip"],
                mac=dev.get("mac", ""),
                hostname=dev.get("hostname", ""),
                vendor=dev.get("vendor", ""),
            )

        status = f"Scan complete: {len(devices)} device(s) found"
        if not devices:
            status += " — check network range or run as administrator"
        self.scan_status.emit(status)
        self.scan_complete.emit(devices)

    def _ensure_local_device(self, devices: list[dict]):
        """Make sure the local machine is in the discovered device list."""
        local_ip = self._local_ip
        if not local_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except OSError:
                return

        if not local_ip or local_ip == "127.0.0.1":
            return

        known_ips = {d["ip"] for d in devices}
        if local_ip not in known_ips:
            local_mac = self._get_local_mac(local_ip)
            hostname = ""
            try:
                hostname = socket.gethostname()
            except OSError:
                pass
            devices.append({
                "ip": local_ip,
                "mac": local_mac,
                "hostname": hostname,
                "vendor": "",
                "is_online": True,
            })

    @staticmethod
    def _get_local_mac(local_ip: str) -> str:
        """Try to get the MAC address of the local interface."""
        try:
            import psutil
            for _iface, addrs in psutil.net_if_addrs().items():
                has_ip = any(
                    a.family == socket.AF_INET and a.address == local_ip
                    for a in addrs
                )
                if has_ip:
                    for a in addrs:
                        if a.family == getattr(psutil, "AF_LINK", -1):
                            return a.address
        except (ImportError, OSError):
            pass
        return ""

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
                    "is_online": True,
                })
            return devices
        except ImportError:
            raise RuntimeError("scapy not installed")

    def _ping_sweep(self) -> list[dict]:
        """Fallback: ping sweep when scapy/raw sockets unavailable."""
        import ipaddress

        network = ipaddress.ip_network(self._network, strict=False)
        devices = []
        param = "-n" if platform.system().lower() == "windows" else "-c"

        for host in network.hosts():
            host_str = str(host)
            self.scan_status.emit(f"Pinging {host_str}...")
            try:
                result = subprocess.run(
                    ["ping", param, "1", "-w", "500", host_str],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if result.returncode == 0:
                    devices.append({
                        "ip": host_str,
                        "mac": "",
                        "hostname": "",
                        "vendor": "",
                        "is_online": True,
                    })
            except (subprocess.TimeoutExpired, OSError):
                continue

        return devices
