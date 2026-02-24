import socket
from PySide6.QtCore import Signal, QThread


class PortScanWorker(QThread):
    """Scans ports on a target host."""

    scan_complete = Signal(list)
    scan_status = Signal(str)

    def __init__(self, target: str = "", ports: str = "1-1024",
                 parent=None):
        super().__init__(parent)
        self._target = target
        self._ports = ports

    def set_target(self, target: str, ports: str = "1-1024"):
        self._target = target
        self._ports = ports

    def run(self):
        if not self._target:
            self.scan_status.emit("No target specified")
            return

        self.scan_status.emit(f"Scanning {self._target}...")
        results = []

        try:
            results = self._nmap_scan()
        except Exception:
            # Fallback to socket scan
            self.scan_status.emit(f"nmap unavailable, using socket scan...")
            results = self._socket_scan()

        self.scan_status.emit(f"Scan complete: {len(results)} port(s) found")
        self.scan_complete.emit(results)

    def _nmap_scan(self) -> list[dict]:
        """Use python-nmap for detailed port scanning."""
        import nmap

        scanner = nmap.PortScanner()
        scanner.scan(self._target, self._ports,
                     arguments="-sV --host-timeout 30s")

        results = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    info = scanner[host][proto][port]
                    results.append({
                        "port": port,
                        "protocol": proto,
                        "state": info.get("state", "unknown"),
                        "service": info.get("name", ""),
                        "version": info.get("version", ""),
                    })
        return results

    def _socket_scan(self) -> list[dict]:
        """Fallback: basic TCP connect scan using sockets."""
        results = []
        port_list = self._parse_ports(self._ports)

        for port in port_list:
            self.scan_status.emit(f"Scanning port {port}...")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self._target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = ""
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "version": "",
                    })
                sock.close()
            except (socket.timeout, OSError):
                continue

        return results

    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        """Parse port specification like '22,80,443' or '1-1024'."""
        result = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    result.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    continue
        return result
