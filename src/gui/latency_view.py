import math

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


class LatencyView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_avg = StatCard("Avg Latency", "—")
        self._card_min = StatCard("Min Latency", "—")
        self._card_max = StatCard("Max Latency", "—")
        self._card_loss = StatCard("Packet Loss", "—")
        cards_layout.addWidget(self._card_avg)
        cards_layout.addWidget(self._card_min)
        cards_layout.addWidget(self._card_max)
        cards_layout.addWidget(self._card_loss)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        self._chart = LiveChart(
            title="Latency Over Time",
            y_label="Latency (ms)",
            num_lines=3,
            line_labels=["Google DNS", "Cloudflare DNS", "Gateway"],
            max_points=300,
        )
        layout.addWidget(self._chart, stretch=1)

        # Status label for unreachable hosts
        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #f38ba8; font-size: 12px; padding: 4px;")
        layout.addWidget(self._status_label)

        self._history: dict[str, list[float]] = {}
        self._target_labels: list[str] = []

    def set_targets(self, labels: list[str]):
        self._target_labels = labels
        # Rebuild chart with correct labels
        layout = self.layout()
        layout.removeWidget(self._chart)
        self._chart.deleteLater()
        self._chart = LiveChart(
            title="Latency Over Time",
            y_label="Latency (ms)",
            num_lines=len(labels),
            line_labels=labels,
            max_points=300,
        )
        # Insert chart before the status label
        layout.insertWidget(layout.count() - 1, self._chart, stretch=1)
        self._history = {label: [] for label in labels}

    def update_latency(self, results: list[dict]):
        """Called with [{label, host, latency_ms, is_alive}, ...]"""
        values = []
        all_latencies = []
        down_hosts = []

        for r in results:
            label = r.get("label", r.get("host", ""))

            if r.get("is_alive"):
                latency = r.get("latency_ms") or 0.0
                values.append(latency)
                all_latencies.append(latency)
            else:
                # Use NaN so PyQtGraph shows a gap instead of a misleading 0ms line
                values.append(float("nan"))
                down_hosts.append(label)

            if label not in self._history:
                self._history[label] = []
            self._history[label].append(values[-1])
            if len(self._history[label]) > 300:
                self._history[label] = self._history[label][-300:]

        if values:
            self._chart.add_data_point(values)

        if all_latencies:
            avg = sum(all_latencies) / len(all_latencies)
            self._card_avg.set_value(f"{avg:.1f} ms")
            self._card_min.set_value(f"{min(all_latencies):.1f} ms")
            self._card_max.set_value(f"{max(all_latencies):.1f} ms")

        total = len(results)
        alive = sum(1 for r in results if r.get("is_alive"))
        if total > 0:
            loss = ((total - alive) / total) * 100
            self._card_loss.set_value(f"{loss:.0f}%")

        # Show which hosts are down
        if down_hosts:
            self._status_label.setText(
                "Unreachable: " + ", ".join(down_hosts)
            )
        else:
            self._status_label.setText("")
