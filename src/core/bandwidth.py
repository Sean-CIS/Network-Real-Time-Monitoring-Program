import psutil
from PySide6.QtCore import Signal

from src.utils.threading import MonitorWorker


class BandwidthMonitor(MonitorWorker):
    """Monitors network bandwidth per interface using psutil."""

    data_ready = Signal(dict)

    def __init__(self, interval_s: float = 1.0, parent=None):
        super().__init__(interval_s=interval_s, parent=parent)
        self._prev_counters: dict | None = None

    def run_cycle(self):
        counters = psutil.net_io_counters(pernic=True)
        result = {}

        if self._prev_counters is not None:
            for iface, curr in counters.items():
                if iface in self._prev_counters:
                    prev = self._prev_counters[iface]
                    # Calculate bytes difference, handle counter wrap
                    sent_diff = curr.bytes_sent - prev.bytes_sent
                    recv_diff = curr.bytes_recv - prev.bytes_recv
                    if sent_diff < 0:
                        sent_diff = curr.bytes_sent
                    if recv_diff < 0:
                        recv_diff = curr.bytes_recv

                    speed_up = sent_diff / self._interval_s
                    speed_down = recv_diff / self._interval_s

                    result[iface] = {
                        "speed_up": speed_up,
                        "speed_down": speed_down,
                        "bytes_sent": curr.bytes_sent,
                        "bytes_recv": curr.bytes_recv,
                        "packets_sent": curr.packets_sent,
                        "packets_recv": curr.packets_recv,
                    }

        self._prev_counters = counters
        if result:
            self.data_ready.emit(result)
