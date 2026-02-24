import unittest
from collections import namedtuple
from unittest.mock import patch, MagicMock


class TestFormatSpeed(unittest.TestCase):
    def test_bytes_per_sec(self):
        from src.gui.bandwidth_view import _format_speed
        self.assertEqual(_format_speed(500), "500 B/s")

    def test_kilobytes_per_sec(self):
        from src.gui.bandwidth_view import _format_speed
        self.assertEqual(_format_speed(1500), "1.5 KB/s")

    def test_megabytes_per_sec(self):
        from src.gui.bandwidth_view import _format_speed
        self.assertEqual(_format_speed(1_500_000), "1.50 MB/s")


class TestFormatBytes(unittest.TestCase):
    def test_bytes(self):
        from src.gui.bandwidth_view import _format_bytes
        self.assertEqual(_format_bytes(500), "500 B")

    def test_kilobytes(self):
        from src.gui.bandwidth_view import _format_bytes
        self.assertEqual(_format_bytes(1500), "1.5 KB")

    def test_megabytes(self):
        from src.gui.bandwidth_view import _format_bytes
        self.assertEqual(_format_bytes(1_500_000), "1.5 MB")

    def test_gigabytes(self):
        from src.gui.bandwidth_view import _format_bytes
        self.assertEqual(_format_bytes(1_500_000_000), "1.50 GB")


class TestBandwidthMonitorWorker(unittest.TestCase):
    @patch("src.core.bandwidth.psutil")
    def test_first_cycle_no_emit(self, mock_psutil):
        """First cycle has no previous counters, result dict is empty."""
        NetIO = namedtuple("NetIO", [
            "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
            "errin", "errout", "dropin", "dropout"
        ])
        mock_psutil.net_io_counters.return_value = {
            "eth0": NetIO(1000, 2000, 10, 20, 0, 0, 0, 0)
        }

        from src.core.bandwidth import BandwidthMonitor
        monitor = BandwidthMonitor(interval_s=1.0)

        # Track emissions
        emitted = []
        monitor.data_ready.connect(lambda d: emitted.append(d))
        monitor.run_cycle()

        # First cycle: no previous data, should not emit
        self.assertEqual(len(emitted), 0)

    @patch("src.core.bandwidth.psutil")
    def test_second_cycle_emits_data(self, mock_psutil):
        """Second cycle computes speed from diff and emits."""
        NetIO = namedtuple("NetIO", [
            "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
            "errin", "errout", "dropin", "dropout"
        ])

        from src.core.bandwidth import BandwidthMonitor
        monitor = BandwidthMonitor(interval_s=1.0)

        emitted = []
        monitor.data_ready.connect(lambda d: emitted.append(d))

        # First cycle
        mock_psutil.net_io_counters.return_value = {
            "eth0": NetIO(1000, 2000, 10, 20, 0, 0, 0, 0)
        }
        monitor.run_cycle()

        # Second cycle with increased counters
        mock_psutil.net_io_counters.return_value = {
            "eth0": NetIO(2000, 5000, 15, 30, 0, 0, 0, 0)
        }
        monitor.run_cycle()

        self.assertEqual(len(emitted), 1)
        data = emitted[0]
        self.assertIn("eth0", data)
        self.assertEqual(data["eth0"]["speed_up"], 1000.0)
        self.assertEqual(data["eth0"]["speed_down"], 3000.0)


if __name__ == "__main__":
    unittest.main()
