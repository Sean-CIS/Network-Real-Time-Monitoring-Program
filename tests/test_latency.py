import unittest
from unittest.mock import patch


class TestPingFunction(unittest.TestCase):
    @patch("src.core.latency.subprocess.run")
    def test_ping_success_linux(self, mock_run):
        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms\n"
        })()

        from src.core.latency import _ping
        result = _ping("8.8.8.8")
        self.assertTrue(result["is_alive"])
        self.assertAlmostEqual(result["latency_ms"], 15.2, places=1)

    @patch("src.core.latency.subprocess.run")
    def test_ping_failure(self, mock_run):
        mock_run.return_value = type("Result", (), {
            "returncode": 1,
            "stdout": "Request timed out.\n"
        })()

        from src.core.latency import _ping
        result = _ping("192.168.1.254")
        self.assertFalse(result["is_alive"])
        self.assertIsNone(result["latency_ms"])

    @patch("src.core.latency.subprocess.run")
    def test_ping_timeout_exception(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=5)

        from src.core.latency import _ping
        result = _ping("10.0.0.1")
        self.assertFalse(result["is_alive"])
        self.assertIsNone(result["latency_ms"])


if __name__ == "__main__":
    unittest.main()
