"""Statistical Anomaly Detection — learns traffic baselines and detects deviations."""

import math
import threading
import time
from datetime import datetime

from PySide6.QtCore import QObject, Signal, QTimer

from src.utils import db


class AnomalyDetector(QObject):
    """Learns normal traffic patterns and alerts on statistical deviations."""

    anomaly_detected = Signal(dict)

    MIN_SAMPLES = 100  # Minimum samples before alerting
    Z_THRESHOLD = 3.0  # Standard deviations for anomaly
    EMA_ALPHA = 0.01   # Exponential moving average smoothing factor
    CHECK_INTERVAL_MS = 10000  # Check every 10 seconds

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lock = threading.Lock()

        # Current metric values (updated by data feeds)
        self._current: dict[str, float] = {
            "bandwidth_bps": 0,
            "connection_count": 0,
            "dns_query_rate": 0,
            "packet_rate": 0,
            "unique_external_ips": 0,
        }

        # Baseline statistics (EMA-based)
        self._baselines: dict[str, dict] = {}
        self._load_baselines()

        # Cooldowns to prevent alert spam
        self._cooldowns: dict[str, float] = {}
        self._cooldown_s = 60.0

        # Check timer
        self._check_timer = QTimer(self)
        self._check_timer.setInterval(self.CHECK_INTERVAL_MS)
        self._check_timer.timeout.connect(self._check_anomalies)
        self._check_timer.start()

    def _load_baselines(self):
        """Load persisted baselines from database with validation."""
        for metric in self._current:
            saved = db.get_baseline(metric)
            if saved:
                mean = saved.get("mean", 0)
                std_dev = saved.get("std_dev", 0)
                sample_count = saved.get("sample_count", 0)

                # Validate loaded values — reject NaN, Inf, negative variance
                if (math.isfinite(mean) and math.isfinite(std_dev)
                        and std_dev >= 0 and sample_count >= 0):
                    self._baselines[metric] = {
                        "mean": mean,
                        "variance": std_dev ** 2,
                        "sample_count": sample_count,
                    }
                else:
                    self._baselines[metric] = {"mean": 0, "variance": 0, "sample_count": 0}
            else:
                self._baselines[metric] = {"mean": 0, "variance": 0, "sample_count": 0}

    def update_bandwidth(self, data: dict):
        """Update bandwidth metric from BandwidthMonitor data."""
        total_bps = sum(v.get("speed_down", 0) + v.get("speed_up", 0) for v in data.values())
        with self._lock:
            self._current["bandwidth_bps"] = total_bps
        self._update_baseline("bandwidth_bps", total_bps)

    def update_connections(self, connections: list[dict]):
        """Update connection metrics from ConnectionsMonitor data."""
        count = len(connections)
        # Count unique external IPs
        external = set()
        for c in connections:
            rip = c.get("remote_ip", "")
            if rip and not rip.startswith(("10.", "192.168.", "172.16.", "127.")):
                external.add(rip)
        ext_count = len(external)

        with self._lock:
            self._current["connection_count"] = count
            self._current["unique_external_ips"] = ext_count
        self._update_baseline("connection_count", count)
        self._update_baseline("unique_external_ips", ext_count)

    def update_dns_rate(self, rate: float):
        """Update DNS query rate metric."""
        with self._lock:
            self._current["dns_query_rate"] = rate
        self._update_baseline("dns_query_rate", rate)

    def update_packet_rate(self, rate: float):
        """Update packet rate metric."""
        with self._lock:
            self._current["packet_rate"] = rate
        self._update_baseline("packet_rate", rate)

    def _update_baseline(self, metric: str, value: float):
        """Update EMA baseline for a metric."""
        with self._lock:
            b = self._baselines[metric]
            b["sample_count"] += 1
            n = b["sample_count"]

            if n == 1:
                b["mean"] = value
                b["variance"] = 0
            else:
                alpha = self.EMA_ALPHA
                old_mean = b["mean"]
                b["mean"] = (1 - alpha) * old_mean + alpha * value
                diff = value - old_mean
                b["variance"] = (1 - alpha) * b["variance"] + alpha * diff * (value - b["mean"])

            # Persist every 50 samples
            if n % 50 != 0:
                return
            std = math.sqrt(max(b["variance"], 0))
            mean = b["mean"]
            count = n

        # DB write outside lock
        try:
            db.upsert_baseline(metric, mean, std, count)
        except Exception:
            pass

    def _check_anomalies(self):
        """Check all metrics for anomalies using z-score."""
        with self._lock:
            current_snapshot = dict(self._current)
            baselines_snapshot = {
                k: dict(v) for k, v in self._baselines.items()
            }

        for metric, value in current_snapshot.items():
            b = baselines_snapshot.get(metric)
            if not b or b["sample_count"] < self.MIN_SAMPLES:
                continue

            mean = b["mean"]
            std = math.sqrt(max(b["variance"], 0))
            if std < 0.001:
                continue

            z_score = (value - mean) / std

            if z_score > self.Z_THRESHOLD:
                self._emit_anomaly(metric, value, mean, std, z_score, "spike")
            elif z_score < -self.Z_THRESHOLD and mean > 0:
                self._emit_anomaly(metric, value, mean, std, z_score, "drop")

    def _emit_anomaly(self, metric: str, value: float, mean: float, std: float,
                      z_score: float, anomaly_type: str):
        key = f"anomaly:{metric}:{anomaly_type}"
        now = time.time()

        with self._lock:
            if now - self._cooldowns.get(key, 0) < self._cooldown_s:
                return
            self._cooldowns[key] = now

        metric_labels = {
            "bandwidth_bps": "Bandwidth",
            "connection_count": "Connection Count",
            "dns_query_rate": "DNS Query Rate",
            "packet_rate": "Packet Rate",
            "unique_external_ips": "Unique External IPs",
        }
        label = metric_labels.get(metric, metric)
        direction = "above" if anomaly_type == "spike" else "below"

        self.anomaly_detected.emit({
            "timestamp": datetime.now().isoformat(),
            "rule_id": f"anomaly_{anomaly_type}",
            "severity": "warning",
            "title": f"Traffic Anomaly: {label} {anomaly_type.title()}",
            "description": (
                f"{label} is {direction} baseline: current={value:.1f}, "
                f"baseline={mean:.1f} +/- {std:.1f}, z-score={z_score:.1f}"
            ),
            "src_ip": "",
            "dst_ip": "",
            "evidence": f"z-score={z_score:.2f}, threshold={self.Z_THRESHOLD}",
            "recommended_action": "Investigate traffic patterns",
        })

    def get_baselines(self) -> dict:
        """Return current baseline statistics for display."""
        with self._lock:
            result = {}
            for metric, b in self._baselines.items():
                result[metric] = {
                    "mean": b["mean"],
                    "std_dev": math.sqrt(max(b["variance"], 0)),
                    "sample_count": b["sample_count"],
                }
        return result
