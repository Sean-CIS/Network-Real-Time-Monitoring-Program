from datetime import datetime

from PySide6.QtCore import Signal, QObject

from src.utils import db


class AlertEngine(QObject):
    """Checks monitoring data against thresholds and emits alerts."""

    alert_triggered = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bandwidth_threshold_mbps = 100.0
        self._latency_threshold_ms = 200.0
        self._device_offline_timeout_s = 60.0
        self._known_devices: set[str] = set()

    def configure(self, bandwidth_mbps: float = 100.0, latency_ms: float = 200.0,
                  offline_timeout_s: float = 60.0):
        self._bandwidth_threshold_mbps = bandwidth_mbps
        self._latency_threshold_ms = latency_ms
        self._device_offline_timeout_s = offline_timeout_s

    def check_bandwidth(self, data: dict):
        """Check bandwidth data for threshold violations."""
        for iface, stats in data.items():
            speed_down_mbps = stats.get("speed_down", 0) / 1_000_000 * 8
            speed_up_mbps = stats.get("speed_up", 0) / 1_000_000 * 8

            if speed_down_mbps > self._bandwidth_threshold_mbps:
                self._emit_alert(
                    alert_type="bandwidth_high",
                    severity="warning",
                    message=f"Download speed {speed_down_mbps:.1f} Mbps exceeds threshold "
                            f"({self._bandwidth_threshold_mbps} Mbps) on {iface}",
                    source=iface,
                )

            if speed_up_mbps > self._bandwidth_threshold_mbps:
                self._emit_alert(
                    alert_type="bandwidth_high",
                    severity="warning",
                    message=f"Upload speed {speed_up_mbps:.1f} Mbps exceeds threshold "
                            f"({self._bandwidth_threshold_mbps} Mbps) on {iface}",
                    source=iface,
                )

    def check_latency(self, results: list[dict]):
        """Check latency results for threshold violations."""
        for r in results:
            latency = r.get("latency_ms")
            host = r.get("host", "")
            label = r.get("label", host)

            if not r.get("is_alive"):
                self._emit_alert(
                    alert_type="latency_high",
                    severity="critical",
                    message=f"Host {label} ({host}) is unreachable",
                    source=host,
                )
            elif latency and latency > self._latency_threshold_ms:
                self._emit_alert(
                    alert_type="latency_high",
                    severity="warning",
                    message=f"Latency to {label} ({host}) is {latency:.0f}ms "
                            f"(threshold: {self._latency_threshold_ms}ms)",
                    source=host,
                )

    def check_devices(self, devices: list[dict]):
        """Check for new devices on the network."""
        current_ips = {d["ip"] for d in devices}
        new_ips = current_ips - self._known_devices

        for ip in new_ips:
            dev = next((d for d in devices if d["ip"] == ip), {})
            mac = dev.get("mac", "unknown")
            self._emit_alert(
                alert_type="device_new",
                severity="info",
                message=f"New device detected: {ip} (MAC: {mac})",
                source=ip,
            )

        self._known_devices = current_ips

    def _emit_alert(self, alert_type: str, severity: str, message: str, source: str = ""):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "source": source,
        }
        db.insert_alert(alert_type, severity, message, source)
        self.alert_triggered.emit(alert)

        # Try desktop notification for warnings and critical
        if severity in ("warning", "critical"):
            try:
                from plyer import notification
                notification.notify(
                    title=f"Network Monitor - {severity.upper()}",
                    message=message,
                    timeout=5,
                )
            except Exception:
                pass
