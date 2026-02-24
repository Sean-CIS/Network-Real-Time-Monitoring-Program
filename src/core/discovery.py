import socket
import subprocess
import platform
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
