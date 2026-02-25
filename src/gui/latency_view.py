import math

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from src.gui import theme
from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


def _latency_color(ms: float) -> str:
    if ms <= 30:
        return theme.GREEN
    elif ms <= 100:
        return theme.AMBER
    return theme.RED


class LatencyView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # Header
        header = QHBoxLayout()
        title = QLabel("[ LATENCY MONITOR ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        # Target status bar
        self._target_status = QLabel("")
        self._target_status.setStyleSheet(
            f"color: {theme.GREEN_DIM}; font-size: 11px; padding: 2px;"
        )
        layout.addWidget(self._target_status)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_avg = StatCard("Avg Latency", "\u2014", sparkline=True)
        self._card_min = StatCard("Min Latency", "\u2014")
        self._card_max = StatCard("Max Latency", "\u2014")
        self._card_loss = StatCard("Packet Loss", "\u2014")
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
        self._status_label.setStyleSheet(
            f"color: {theme.RED}; font-size: 12px; padding: 4px;"
        )
        layout.addWidget(self._status_label)

        self._history: dict[str, list[float]] = {}
        self._target_labels: list[str] = []

    def set_targets(self, labels: list[str]):
        self._target_labels = labels
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
        layout.insertWidget(layout.count() - 1, self._chart, stretch=1)
        self._history = {label: [] for label in labels}

    def update_latency(self, results: list[dict]):
        values = []
        all_latencies = []
        down_hosts = []
        target_parts = []

        for r in results:
            label = r.get("label", r.get("host", ""))

            if r.get("is_alive"):
                latency = r.get("latency_ms") or 0.0
                values.append(latency)
                all_latencies.append(latency)
                color = _latency_color(latency)
                target_parts.append(
                    f'<span style="color: {color};">\u25cf {label}: {latency:.1f}ms</span>'
                )
            else:
                values.append(float("nan"))
                down_hosts.append(label)
                target_parts.append(
                    f'<span style="color: {theme.RED};">\u25cf {label}: DOWN</span>'
                )

            if label not in self._history:
                self._history[label] = []
            self._history[label].append(values[-1])
            if len(self._history[label]) > 300:
                self._history[label] = self._history[label][-300:]

        if values:
            self._chart.add_data_point(values)

        # Update target status bar
        self._target_status.setText("  |  ".join(target_parts))
        self._target_status.setTextFormat(1)  # RichText

        if all_latencies:
            avg = sum(all_latencies) / len(all_latencies)
            self._card_avg.set_value(f"{avg:.1f} ms")
            self._card_avg.add_spark_point(avg)
            self._card_min.set_value(f"{min(all_latencies):.1f} ms")
            self._card_max.set_value(f"{max(all_latencies):.1f} ms")

            # Color-code avg latency card
            color = _latency_color(avg)
            for child in self._card_avg.findChildren(QLabel):
                if "ms" in child.text():
                    child.setStyleSheet(
                        f"color: {color}; font-size: 20px; font-weight: bold;"
                    )
                    break

        total = len(results)
        alive = sum(1 for r in results if r.get("is_alive"))
        if total > 0:
            loss = ((total - alive) / total) * 100
            self._card_loss.set_value(f"{loss:.0f}%")
            # Red if any packet loss
            if loss > 0:
                for child in self._card_loss.findChildren(QLabel):
                    if "%" in child.text():
                        child.setStyleSheet(
                            f"color: {theme.RED}; font-size: 20px; font-weight: bold;"
                        )
                        break

        if down_hosts:
            self._status_label.setText(
                "\u26a0 Unreachable: " + ", ".join(down_hosts)
            )
        else:
            self._status_label.setText("")
