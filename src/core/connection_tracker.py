"""Active network connection tracker with outbound monitoring and per-process bandwidth."""

from datetime import datetime

from PySide6.QtCore import Signal

from src.core.threat_detector import SUSPICIOUS_PORTS
from src.utils.threading import MonitorWorker


class ConnectionTracker(MonitorWorker):
    """Monitors active network connections (like netstat) in real-time."""

    data_ready = Signal(list)
    new_destination = Signal(dict)  # first-time remote IP detected

    def __init__(self, interval_s: float = 3.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)
        self._known_destinations: set[str] = set()
        self._prev_io: dict[int, tuple[int, int]] = {}  # pid -> (read, write)

    def run_cycle(self):
        import psutil

        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.data_ready.emit([])
            return

        # Refresh per-process IO counters
        current_io: dict[int, tuple[int, int]] = {}
        results = []
        for c in conns:
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                proc_name = proc.name() if proc else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                proc_name = ""

            local_addr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            remote_ip = c.raddr.ip if c.raddr else ""
            remote_port = c.raddr.port if c.raddr else None

            highlight = False
            if remote_port and remote_port in SUSPICIOUS_PORTS:
                highlight = True
            elif not proc_name and c.status == "ESTABLISHED" and remote_addr:
                highlight = True

            # Per-process bandwidth via IO counters
            bytes_in = 0
            bytes_out = 0
            if c.pid and proc:
                try:
                    io = proc.io_counters()
                    current_read = io.read_bytes
                    current_write = io.write_bytes
                    current_io[c.pid] = (current_read, current_write)
                    if c.pid in self._prev_io:
                        prev_read, prev_write = self._prev_io[c.pid]
                        bytes_in = max(0, current_read - prev_read)
                        bytes_out = max(0, current_write - prev_write)
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess, AttributeError):
                    pass

            # Check for new destination
            is_new = False
            if remote_ip and remote_ip not in self._known_destinations:
                self._known_destinations.add(remote_ip)
                is_new = True
                self.new_destination.emit({
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": proc_name or "Unknown",
                    "timestamp": datetime.now().isoformat(),
                })

            results.append({
                "pid": str(c.pid) if c.pid else "",
                "process": proc_name or "Unknown",
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "state": c.status,
                "highlight": highlight,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "is_new_dest": is_new,
            })

        self._prev_io = current_io
        self.data_ready.emit(results)
