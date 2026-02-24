import statistics
import time
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
        self._cooldown_period_s = 300.0
        self._cooldowns: dict[str, float] = {}
        self._active_conditions: set[str] = set()
        self._known_devices: set[str] = set()

        # Bandwidth anomaly detection
        self._bandwidth_history: list[float] = []
        self._bw_window_size = 60

    def configure(self, bandwidth_mbps: float = 100.0, latency_ms: float = 200.0,
                  offline_timeout_s: float = 60.0, cooldown_s: float = 300.0):
        self._bandwidth_threshold_mbps = bandwidth_mbps
        self._latency_threshold_ms = latency_ms
        self._device_offline_timeout_s = offline_timeout_s
        self._cooldown_period_s = cooldown_s

    def reset(self):
        """Clear all cooldowns and active conditions (e.g. after clearing alerts)."""
        self._cooldowns.clear()
        self._active_conditions.clear()

    def check_bandwidth(self, data: dict):
        """Check bandwidth data for threshold violations and anomalies."""
        for iface, stats in data.items():
            speed_down_mbps = stats.get("speed_down", 0) / 1_000_000 * 8
            speed_up_mbps = stats.get("speed_up", 0) / 1_000_000 * 8

            down_key = f"bandwidth_high:{iface}:down"
            if speed_down_mbps > self._bandwidth_threshold_mbps:
                self._emit_alert(
                    alert_type="bandwidth_high",
                    severity="warning",
                    message=f"Download speed {speed_down_mbps:.1f} Mbps exceeds threshold "
                            f"({self._bandwidth_threshold_mbps} Mbps) on {iface}",
                    source=iface,
                    condition_key=down_key,
                )
            else:
                self._active_conditions.discard(down_key)

            up_key = f"bandwidth_high:{iface}:up"
            if speed_up_mbps > self._bandwidth_threshold_mbps:
                self._emit_alert(
                    alert_type="bandwidth_high",
                    severity="warning",
                    message=f"Upload speed {speed_up_mbps:.1f} Mbps exceeds threshold "
                            f"({self._bandwidth_threshold_mbps} Mbps) on {iface}",
                    source=iface,
                    condition_key=up_key,
                )
            else:
                self._active_conditions.discard(up_key)

        # Bandwidth anomaly detection (statistical)
        total_bps = sum(
            v.get("speed_down", 0) + v.get("speed_up", 0) for v in data.values()
        )
        self._bandwidth_history.append(total_bps)
        if len(self._bandwidth_history) > self._bw_window_size:
            self._bandwidth_history.pop(0)

        anomaly_key = "bandwidth_anomaly:global"
        if len(self._bandwidth_history) >= 60:
            baseline = self._bandwidth_history[:-1]
            mean = statistics.mean(baseline)
            stdev = statistics.stdev(baseline) if len(baseline) > 1 else 0
            if stdev > 1000 and mean > 10000 and total_bps > mean + 3 * stdev:
                self._emit_alert(
                    alert_type="bandwidth_anomaly",
                    severity="warning",
                    message=(
                        f"Bandwidth anomaly: {total_bps / 1_000_000:.1f} MB/s "
                        f"(baseline: {mean / 1_000_000:.1f} +/- "
                        f"{stdev / 1_000_000:.1f} MB/s)"
                    ),
                    source="bandwidth",
                    condition_key=anomaly_key,
                )
            else:
                self._active_conditions.discard(anomaly_key)

    def check_latency(self, results: list[dict]):
        """Check latency results for threshold violations."""
        for r in results:
            latency = r.get("latency_ms")
            host = r.get("host", "")
            label = r.get("label", host)

            unreachable_key = f"latency_high:{host}:unreachable"
            high_key = f"latency_high:{host}:high"

            if not r.get("is_alive"):
                self._active_conditions.discard(high_key)
                self._emit_alert(
                    alert_type="latency_high",
                    severity="critical",
                    message=f"Host {label} ({host}) is unreachable",
                    source=host,
                    condition_key=unreachable_key,
                )
            elif latency and latency > self._latency_threshold_ms:
                self._active_conditions.discard(unreachable_key)
                self._emit_alert(
                    alert_type="latency_high",
                    severity="warning",
                    message=f"Latency to {label} ({host}) is {latency:.0f}ms "
                            f"(threshold: {self._latency_threshold_ms}ms)",
                    source=host,
                    condition_key=high_key,
                )
            else:
                self._active_conditions.discard(unreachable_key)
                self._active_conditions.discard(high_key)

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

    def check_rogue_devices(self, devices: list[dict]):
        """Compare current devices against baseline. Flag new MACs as rogue."""
        baseline = db.get_baseline_devices()
        baseline_macs = {d["mac"] for d in baseline}

        for dev in devices:
            mac = dev.get("mac", "")
            if not mac:
                continue
            if mac not in baseline_macs:
                db.upsert_baseline_device(mac, dev.get("ip", ""))
                db.insert_security_event(
                    severity="warning",
                    event_type="rogue_device",
                    source_ip=dev.get("ip", ""),
                    description=(
                        f"New device on network: {dev.get('ip', '?')} "
                        f"MAC: {mac} Vendor: {dev.get('vendor', 'Unknown')}"
                    ),
                )
            else:
                # Update IP for existing baseline entry
                db.upsert_baseline_device(mac, dev.get("ip", ""))

    def _emit_alert(self, alert_type: str, severity: str, message: str,
                    source: str = "", condition_key: str = ""):
        key = condition_key or f"{alert_type}:{source}"

        # If this condition is already active, suppress completely
        if key in self._active_conditions:
            return

        # Cooldown check for flapping protection (rapid on/off/on)
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self._cooldown_period_s:
            return

        # Mark condition as active and record cooldown timestamp
        self._active_conditions.add(key)
        self._cooldowns[key] = now

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
