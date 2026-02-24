"""Active network connection tracker using psutil."""

from PySide6.QtCore import Signal

from src.core.threat_detector import SUSPICIOUS_PORTS
from src.utils.threading import MonitorWorker


class ConnectionTracker(MonitorWorker):
    """Monitors active network connections (like netstat) in real-time."""

    data_ready = Signal(list)

    def __init__(self, interval_s: float = 3.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)

    def run_cycle(self):
        import psutil

        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.data_ready.emit([])
            return

        results = []
        for c in conns:
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                proc_name = proc.name() if proc else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                proc_name = ""

            local_addr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            remote_port = c.raddr.port if c.raddr else None

            highlight = False
            if remote_port and remote_port in SUSPICIOUS_PORTS:
                highlight = True
            elif not proc_name and c.status == "ESTABLISHED" and remote_addr:
                highlight = True

            results.append({
                "pid": str(c.pid) if c.pid else "",
                "process": proc_name or "Unknown",
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "state": c.status,
                "highlight": highlight,
            })

        self.data_ready.emit(results)
