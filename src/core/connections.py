"""Active network connections monitor using psutil."""

import psutil
from PySide6.QtCore import Signal

from src.utils.threading import MonitorWorker

# Well-known port → protocol name mapping
PORT_PROTOCOLS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# TCP states
TCP_STATES = {
    "ESTABLISHED": "ESTABLISHED",
    "SYN_SENT": "SYN_SENT",
    "SYN_RECV": "SYN_RECV",
    "FIN_WAIT1": "FIN_WAIT1",
    "FIN_WAIT2": "FIN_WAIT2",
    "TIME_WAIT": "TIME_WAIT",
    "CLOSE": "CLOSED",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "LAST_ACK": "LAST_ACK",
    "LISTEN": "LISTEN",
    "CLOSING": "CLOSING",
    "NONE": "NONE",
}


class ConnectionsMonitor(MonitorWorker):
    """Polls active network connections and emits enriched connection data."""

    data_ready = Signal(list)  # list of connection dicts

    def __init__(self, interval_s: float = 2.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)

    def run_cycle(self):
        connections = []
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            raw = psutil.net_connections(kind="inet4")
        except Exception:
            raw = []

        for conn in raw:
            if not conn.raddr:
                continue

            local_ip = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            # Classify protocol by remote port
            proto = "TCP" if conn.type == 1 else "UDP"
            service = PORT_PROTOCOLS.get(remote_port, "")
            if not service:
                service = PORT_PROTOCOLS.get(local_port, "")

            # Get process name
            proc_name = ""
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = f"PID:{conn.pid}"

            # Get connection status
            status = getattr(conn, "status", "NONE")
            if status and hasattr(status, "name"):
                status = status.name
            status = TCP_STATES.get(str(status), str(status))

            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": proto,
                "service": service or f":{remote_port}",
                "status": status,
                "pid": conn.pid or 0,
                "process": proc_name,
            })

        self.data_ready.emit(connections)
