import subprocess
import platform
from PySide6.QtCore import Signal

from src.utils.threading import MonitorWorker


def _ping(host: str, timeout: float = 2.0) -> dict:
    """Ping a host using system ping command and parse the result."""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(int(timeout * 1000)) if platform.system().lower() == "windows" else str(int(timeout))

        result = subprocess.run(
            ["ping", param, "1", timeout_param, timeout_val, host],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )

        if result.returncode == 0:
            output = result.stdout
            # Parse latency from output
            latency = None
            if platform.system().lower() == "windows":
                for line in output.split("\n"):
                    if "time=" in line.lower() or "time<" in line.lower():
                        for part in line.split():
                            if part.lower().startswith("time=") or part.lower().startswith("time<"):
                                val = part.split("=")[-1] if "=" in part else part.split("<")[-1]
                                val = val.replace("ms", "").strip()
                                try:
                                    latency = float(val)
                                except ValueError:
                                    pass
            else:
                for line in output.split("\n"):
                    if "time=" in line:
                        for part in line.split():
                            if part.startswith("time="):
                                try:
                                    latency = float(part.split("=")[1])
                                except (ValueError, IndexError):
                                    pass

            return {"is_alive": True, "latency_ms": latency}
        return {"is_alive": False, "latency_ms": None}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"is_alive": False, "latency_ms": None}


class LatencyMonitor(MonitorWorker):
    """Monitors latency to configured targets."""

    data_ready = Signal(list)

    def __init__(self, targets: list[dict] | None = None, interval_s: float = 2.0,
                 parent=None):
        super().__init__(interval_s=interval_s, parent=parent)
        self._targets = targets or []

    def set_targets(self, targets: list[dict]):
        self._targets = targets

    def run_cycle(self):
        results = []
        for target in self._targets:
            host = target.get("host", "")
            label = target.get("label", host)
            if not host:
                continue
            ping_result = _ping(host)
            results.append({
                "host": host,
                "label": label,
                "latency_ms": ping_result["latency_ms"],
                "is_alive": ping_result["is_alive"],
            })
        if results:
            self.data_ready.emit(results)
