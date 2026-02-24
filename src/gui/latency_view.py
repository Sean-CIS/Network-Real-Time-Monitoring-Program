from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

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
        layout.addWidget(self._chart, stretch=1)
        self._history = {label: [] for label in labels}

    def update_latency(self, results: list[dict]):
        """Called with [{label, host, latency_ms, is_alive}, ...]"""
        values = []
        all_latencies = []

        for r in results:
            label = r.get("label", r.get("host", ""))
            latency = r.get("latency_ms", 0) or 0
            values.append(latency)

            if label not in self._history:
                self._history[label] = []
            self._history[label].append(latency)
            if len(self._history[label]) > 300:
                self._history[label] = self._history[label][-300:]

            if r.get("is_alive"):
                all_latencies.append(latency)

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
