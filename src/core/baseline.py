"""Network baseline learning and deviation detection."""

import json
import statistics
import time
from datetime import datetime

from PySide6.QtCore import Signal

from src.utils import db
from src.utils.threading import MonitorWorker


class NetworkBaseline(MonitorWorker):
    """Learns normal network patterns and detects deviations.

    During the learning phase (first 1000 samples or 24h, whichever comes first),
    it builds a baseline of normal bandwidth, connection counts, and protocol
    distribution. After learning, it compares live metrics and emits events.
    """

    deviation_detected = Signal(dict)   # security event dict
    mode_changed = Signal(str)          # "learning" or "monitoring"

    _LEARNING_SAMPLES = 1000
    _LEARNING_DURATION_S = 86400  # 24 hours

    def __init__(self, interval_s: float = 10.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)
        self._is_learning = True
        self._learning_start: float = time.time()
        self._sample_count = 0

        # Learning data
        self._bw_samples: list[float] = []
        self._conn_count_samples: list[int] = []

        # Baseline (after learning)
        self._bw_mean: float = 0.0
        self._bw_stdev: float = 0.0
        self._conn_mean: float = 0.0
        self._conn_stdev: float = 0.0

        # Live data (set from outside)
        self._current_bw: float = 0.0
        self._current_conn_count: int = 0

        # Try to restore from DB
        self._try_restore_baseline()

    def _try_restore_baseline(self):
        """Try to restore a previously learned baseline from the database."""
        try:
            data = db.get_baseline_metric("network_baseline_v1")
            if data:
                bl = json.loads(data)
                self._bw_mean = bl.get("bw_mean", 0)
                self._bw_stdev = bl.get("bw_stdev", 0)
                self._conn_mean = bl.get("conn_mean", 0)
                self._conn_stdev = bl.get("conn_stdev", 0)
                self._sample_count = bl.get("sample_count", 0)
                if self._sample_count >= self._LEARNING_SAMPLES:
                    self._is_learning = False
        except Exception:
            pass

    def feed_bandwidth(self, total_bps: float):
        """Feed current bandwidth data."""
        self._current_bw = total_bps

    def feed_connection_count(self, count: int):
        """Feed current active connection count."""
        self._current_conn_count = count

    @property
    def is_learning(self) -> bool:
        return self._is_learning

    def run_cycle(self):
        if self._is_learning:
            self._learn()
        else:
            self._detect()

    def _learn(self):
        """Collect a sample during the learning phase."""
        self._bw_samples.append(self._current_bw)
        self._conn_count_samples.append(self._current_conn_count)
        self._sample_count += 1

        elapsed = time.time() - self._learning_start
        done = (self._sample_count >= self._LEARNING_SAMPLES
                or elapsed >= self._LEARNING_DURATION_S)

        if done and len(self._bw_samples) >= 30:
            # Compute baseline
            self._bw_mean = statistics.mean(self._bw_samples)
            self._bw_stdev = (statistics.stdev(self._bw_samples)
                              if len(self._bw_samples) > 1 else 0)
            self._conn_mean = statistics.mean(self._conn_count_samples)
            self._conn_stdev = (statistics.stdev(self._conn_count_samples)
                                if len(self._conn_count_samples) > 1 else 0)

            # Persist to DB
            db.upsert_baseline_metric("network_baseline_v1", json.dumps({
                "bw_mean": self._bw_mean,
                "bw_stdev": self._bw_stdev,
                "conn_mean": self._conn_mean,
                "conn_stdev": self._conn_stdev,
                "sample_count": self._sample_count,
                "completed_at": datetime.now().isoformat(),
            }))

            self._is_learning = False
            self.mode_changed.emit("monitoring")

            # Free learning data
            self._bw_samples.clear()
            self._conn_count_samples.clear()

    def _detect(self):
        """Compare live metrics against the baseline."""
        # Bandwidth deviation
        if (self._bw_stdev > 0
                and self._bw_mean > 10_000
                and self._current_bw > self._bw_mean + 4 * self._bw_stdev):
            self.deviation_detected.emit({
                "timestamp": datetime.now().isoformat(),
                "severity": "warning",
                "event_type": "baseline_deviation",
                "source_ip": "",
                "dest_ip": "",
                "description": (
                    f"Bandwidth deviation: {self._current_bw / 1_000:.0f} KB/s "
                    f"(baseline: {self._bw_mean / 1_000:.0f} +/- "
                    f"{self._bw_stdev / 1_000:.0f} KB/s)"
                ),
                "raw_details": json.dumps({
                    "metric": "bandwidth",
                    "current": self._current_bw,
                    "mean": self._bw_mean,
                    "stdev": self._bw_stdev,
                }),
            })

        # Connection count deviation
        if (self._conn_stdev > 0
                and self._conn_mean > 5
                and self._current_conn_count > self._conn_mean + 4 * self._conn_stdev):
            self.deviation_detected.emit({
                "timestamp": datetime.now().isoformat(),
                "severity": "info",
                "event_type": "baseline_deviation",
                "source_ip": "",
                "dest_ip": "",
                "description": (
                    f"Connection count deviation: {self._current_conn_count} "
                    f"(baseline: {self._conn_mean:.0f} +/- "
                    f"{self._conn_stdev:.0f})"
                ),
                "raw_details": json.dumps({
                    "metric": "connections",
                    "current": self._current_conn_count,
                    "mean": self._conn_mean,
                    "stdev": self._conn_stdev,
                }),
            })
