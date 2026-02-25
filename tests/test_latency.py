import unittest
from unittest.mock import patch


class TestPingFunction(unittest.TestCase):
    @patch("src.core.latency.subprocess.run")
    @patch("src.core.latency.shutil.which", return_value="/usr/bin/ping")
    def test_ping_success_linux(self, mock_which, mock_run):
        # Reset cached ping method so detection re-runs
        import src.core.latency as lat
        lat._PING_METHOD = None

        mock_run.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms\n"
        })()

        result = lat._ping("8.8.8.8")
        self.assertTrue(result["is_alive"])
        self.assertAlmostEqual(result["latency_ms"], 15.2, places=1)

    @patch("src.core.latency.subprocess.run")
    @patch("src.core.latency.shutil.which", return_value="/usr/bin/ping")
    def test_ping_failure(self, mock_which, mock_run):
        import src.core.latency as lat
        lat._PING_METHOD = None

        mock_run.return_value = type("Result", (), {
            "returncode": 1,
            "stdout": "Request timed out.\n"
        })()

        result = lat._ping("192.168.1.254")
        self.assertFalse(result["is_alive"])
        self.assertIsNone(result["latency_ms"])

    @patch("src.core.latency.subprocess.run")
    @patch("src.core.latency.shutil.which", return_value="/usr/bin/ping")
    def test_ping_timeout_exception(self, mock_which, mock_run):
        import subprocess
        import src.core.latency as lat
        lat._PING_METHOD = None

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=5)

        result = lat._ping("10.0.0.1")
        self.assertFalse(result["is_alive"])
        self.assertIsNone(result["latency_ms"])

    def test_no_ping_available(self):
        """When no ping method exists, _ping returns graceful failure."""
        import src.core.latency as lat
        lat._PING_METHOD = "none"

        result = lat._ping("8.8.8.8")
        self.assertFalse(result["is_alive"])
        self.assertIsNone(result["latency_ms"])
        self.assertEqual(result.get("error"), "no_ping_available")


if __name__ == "__main__":
    unittest.main()
