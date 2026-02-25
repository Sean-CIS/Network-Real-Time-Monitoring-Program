import shutil
import subprocess
import platform
import re
from PySide6.QtCore import Signal

from src.utils.threading import MonitorWorker

# Ping method detection — done once at import time
_PING_METHOD = None  # 'system', 'icmplib', or None


def _detect_ping_method():
    global _PING_METHOD
    if _PING_METHOD is not None:
        return _PING_METHOD
    # Try system ping first
    if shutil.which("ping"):
        _PING_METHOD = "system"
        return _PING_METHOD
    # Try icmplib (pure Python ICMP)
    try:
        from icmplib import ping as _icmp_ping  # noqa: F401
        _PING_METHOD = "icmplib"
        return _PING_METHOD
    except ImportError:
        pass
    _PING_METHOD = "none"
    return _PING_METHOD


def _detect_gateway() -> str:
    """Auto-detect default gateway IP from system routing table."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        # Parse "default via X.X.X.X dev ..."
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    # Windows fallback
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                return parts[2]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _ping(host: str, timeout: float = 2.0) -> dict:
    """Ping a host — tries system ping, then icmplib, then gives up gracefully."""
    method = _detect_ping_method()

    if method == "icmplib":
        return _ping_icmplib(host, timeout)
    elif method == "system":
        return _ping_system(host, timeout)
    else:
        return {"is_alive": False, "latency_ms": None, "error": "no_ping_available"}


def _ping_icmplib(host: str, timeout: float = 2.0) -> dict:
    """Pure Python ICMP ping via icmplib."""
    try:
        from icmplib import ping as icmp_ping
        result = icmp_ping(host, count=1, timeout=timeout, privileged=False)
        if result.is_alive:
            return {"is_alive": True, "latency_ms": result.avg_rtt}
        return {"is_alive": False, "latency_ms": None}
    except Exception:
        return {"is_alive": False, "latency_ms": None}


def _ping_system(host: str, timeout: float = 2.0) -> dict:
    """Ping using system ping command."""
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
        self._ping_available = True
        self._failure_counts: dict[str, int] = {}  # track consecutive failures per host
        self._warned_no_ping = False
        self._resolve_auto_targets()

    def _resolve_auto_targets(self):
        """Resolve 'auto' host targets to actual gateway IP."""
        for target in self._targets:
            if target.get("host", "").lower() == "auto":
                gw = _detect_gateway()
                if gw:
                    target["host"] = gw
                    target["label"] = f"Gateway ({gw})"
                else:
                    target["host"] = ""
                    target["label"] = "Gateway (not found)"

    def set_targets(self, targets: list[dict]):
        self._targets = targets
        self._resolve_auto_targets()

    def run_cycle(self):
        method = _detect_ping_method()
        if method == "none" and not self._warned_no_ping:
            self._warned_no_ping = True
            self.error_occurred.emit(
                "No ping capability available (no ping binary, no icmplib). "
                "Latency monitoring disabled."
            )
            # Emit a single result showing targets as unknown, not as CRITICAL failures
            results = []
            for target in self._targets:
                host = target.get("host", "")
                label = target.get("label", host)
                if host:
                    results.append({
                        "host": host,
                        "label": label,
                        "latency_ms": None,
                        "is_alive": None,  # None = unknown, not False = down
                    })
            if results:
                self.data_ready.emit(results)
            return

        if method == "none":
            return  # Already warned, silently skip

        results = []
        for target in self._targets:
            host = target.get("host", "")
            label = target.get("label", host)
            if not host:
                continue
            ping_result = _ping(host)

            # Track consecutive failures — suppress after 3 consecutive failures
            if not ping_result.get("is_alive"):
                self._failure_counts[host] = self._failure_counts.get(host, 0) + 1
            else:
                self._failure_counts[host] = 0

            # After 3 consecutive failures, report as unknown instead of down
            # This prevents infinite CRITICAL alert spam
            if self._failure_counts.get(host, 0) > 3:
                ping_result["is_alive"] = None  # unknown, not down

            results.append({
                "host": host,
                "label": label,
                "latency_ms": ping_result["latency_ms"],
                "is_alive": ping_result["is_alive"],
            })
        if results:
            self.data_ready.emit(results)
