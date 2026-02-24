"""ARP cache monitoring — detect MAC address changes."""

import platform
import re
import subprocess
from datetime import datetime

from PySide6.QtCore import Signal

from src.utils.threading import MonitorWorker


class ARPMonitor(MonitorWorker):
    """Monitors the system ARP table for MAC address changes."""

    arp_change = Signal(dict)       # {ip, old_mac, new_mac, timestamp}
    arp_table_updated = Signal(list)  # full ARP table as list of dicts

    def __init__(self, interval_s: float = 10.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)
        self._arp_cache: dict[str, str] = {}  # ip -> mac

    def run_cycle(self):
        entries = self._read_arp_table()
        changes = []

        for entry in entries:
            ip = entry["ip"]
            mac = entry["mac"]
            if ip in self._arp_cache:
                old_mac = self._arp_cache[ip]
                if old_mac != mac:
                    change = {
                        "ip": ip,
                        "old_mac": old_mac,
                        "new_mac": mac,
                        "timestamp": datetime.now().isoformat(),
                    }
                    changes.append(change)
                    self.arp_change.emit(change)
            self._arp_cache[ip] = mac

        self.arp_table_updated.emit(entries)

    @staticmethod
    def _read_arp_table() -> list[dict]:
        """Read the system ARP table."""
        entries = []

        if platform.system().lower() == "linux":
            entries = ARPMonitor._read_proc_arp()
        else:
            entries = ARPMonitor._read_arp_command()

        return entries

    @staticmethod
    def _read_proc_arp() -> list[dict]:
        """Read /proc/net/arp on Linux."""
        entries = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        entries.append({"ip": ip, "mac": mac})
        except (OSError, IOError):
            entries = ARPMonitor._read_arp_command()
        return entries

    @staticmethod
    def _read_arp_command() -> list[dict]:
        """Parse output of 'arp -a' command."""
        entries = []
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            # Pattern matches "hostname (IP) at MAC ..."
            pattern = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
            for match in pattern.finditer(result.stdout):
                ip = match.group(1)
                mac = match.group(2)
                if mac and mac != "00:00:00:00:00:00":
                    entries.append({"ip": ip, "mac": mac})
        except (subprocess.TimeoutExpired, OSError):
            pass
        return entries
