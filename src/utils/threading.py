from PySide6.QtCore import QThread, Signal, QMutex


class MonitorWorker(QThread):
    """Base class for background monitoring threads.

    Subclasses should implement `run_cycle()` which is called repeatedly
    with `interval_s` seconds between cycles.
    """

    error_occurred = Signal(str)

    def __init__(self, interval_s: float = 1.0, parent=None):
        super().__init__(parent)
        self._interval_s = interval_s
        self._running = False
        self._mutex = QMutex()

    @property
    def interval_s(self) -> float:
        return self._interval_s

    @interval_s.setter
    def interval_s(self, value: float):
        self._interval_s = value

    def run(self):
        self._running = True
        while self._running:
            try:
                self.run_cycle()
            except Exception as e:
                self.error_occurred.emit(str(e))
            self.msleep(int(self._interval_s * 1000))

    def run_cycle(self):
        raise NotImplementedError("Subclasses must implement run_cycle()")

    def stop(self):
        self._running = False
        self.wait(int(self._interval_s * 2000 + 1000))
