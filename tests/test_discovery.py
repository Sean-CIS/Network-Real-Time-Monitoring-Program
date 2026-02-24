import unittest
from unittest.mock import patch, MagicMock


class TestDiscoveryLocalDevice(unittest.TestCase):
    """Tests for DiscoveryWorker._ensure_local_device."""

    def _make_worker(self, local_ip="10.0.0.5"):
        from src.core.discovery import DiscoveryWorker

        worker = DiscoveryWorker(network="10.0.0.0/24", local_ip=local_ip)
        return worker

    @patch("src.core.discovery.socket.gethostname", return_value="test-host")
    def test_adds_local_device_when_missing(self, mock_hostname):
        worker = self._make_worker("10.0.0.5")
        devices = []
        worker._ensure_local_device(devices)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "10.0.0.5")
        self.assertTrue(devices[0]["is_online"])

    @patch("src.core.discovery.socket.gethostname", return_value="test-host")
    def test_skips_if_already_present(self, mock_hostname):
        worker = self._make_worker("10.0.0.5")
        devices = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff",
                     "hostname": "", "vendor": "", "is_online": True}]
        worker._ensure_local_device(devices)

        self.assertEqual(len(devices), 1)  # No duplicate added

    def test_skips_localhost(self):
        worker = self._make_worker("127.0.0.1")
        devices = []
        worker._ensure_local_device(devices)

        self.assertEqual(len(devices), 0)

    @patch("src.core.discovery.socket.socket")
    def test_skips_empty_ip_when_detection_fails(self, mock_socket_cls):
        """When local_ip is empty and fallback detection also fails, no device added."""
        mock_socket_cls.return_value.connect.side_effect = OSError("no route")
        worker = self._make_worker("")
        devices = []
        worker._ensure_local_device(devices)

        self.assertEqual(len(devices), 0)


class TestPortParser(unittest.TestCase):
    def test_parse_range(self):
        from src.core.port_scanner import PortScanWorker
        result = PortScanWorker._parse_ports("1-5")
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_parse_comma_separated(self):
        from src.core.port_scanner import PortScanWorker
        result = PortScanWorker._parse_ports("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_parse_mixed(self):
        from src.core.port_scanner import PortScanWorker
        result = PortScanWorker._parse_ports("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_parse_invalid(self):
        from src.core.port_scanner import PortScanWorker
        result = PortScanWorker._parse_ports("abc")
        self.assertEqual(result, [])

    def test_parse_empty(self):
        from src.core.port_scanner import PortScanWorker
        result = PortScanWorker._parse_ports("")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
