import unittest
from unittest.mock import patch, mock_open, MagicMock


class TestDetectNetworkInfo(unittest.TestCase):
    def test_returns_dict_with_required_keys(self):
        from src.utils.network import detect_network_info

        info = detect_network_info()
        self.assertIsInstance(info, dict)
        self.assertIn("gateway_ip", info)
        self.assertIn("local_ip", info)
        self.assertIn("subnet_cidr", info)

    def test_values_are_strings(self):
        from src.utils.network import detect_network_info

        info = detect_network_info()
        for key in ("gateway_ip", "local_ip", "subnet_cidr"):
            self.assertIsInstance(info[key], str)
            self.assertTrue(len(info[key]) > 0, f"{key} should not be empty")


class TestGatewayFromProcRoute(unittest.TestCase):
    PROC_NET_ROUTE_HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"

    @patch(
        "builtins.open",
        mock_open(
            read_data=(
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
            )
        ),
    )
    def test_parses_gateway_correctly(self):
        """0101A8C0 in /proc/net/route (little-endian) = 192.168.1.1."""
        from src.utils.network import _gateway_from_proc_route

        gw = _gateway_from_proc_route()
        self.assertEqual(gw, "192.168.1.1")

    @patch(
        "builtins.open",
        mock_open(
            read_data=(
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
            )
        ),
    )
    def test_parses_10_network_gateway(self):
        """0100000A in /proc/net/route (little-endian) = 10.0.0.1."""
        from src.utils.network import _gateway_from_proc_route

        gw = _gateway_from_proc_route()
        self.assertEqual(gw, "10.0.0.1")

    @patch(
        "builtins.open",
        mock_open(
            read_data=(
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
            )
        ),
    )
    def test_no_default_route_returns_empty(self):
        """When no default route (destination 00000000) exists, return empty."""
        from src.utils.network import _gateway_from_proc_route

        gw = _gateway_from_proc_route()
        self.assertEqual(gw, "")

    @patch("builtins.open", side_effect=OSError("No such file"))
    def test_missing_proc_file_returns_empty(self, mock_file):
        from src.utils.network import _gateway_from_proc_route

        gw = _gateway_from_proc_route()
        self.assertEqual(gw, "")


class TestIsAdmin(unittest.TestCase):
    def test_returns_bool(self):
        from src.utils.network import is_admin

        result = is_admin()
        self.assertIsInstance(result, bool)


class TestDetectLocalIp(unittest.TestCase):
    @patch("src.utils.network.socket.socket")
    def test_udp_trick_returns_ip(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.50", 12345)
        mock_socket_cls.return_value = mock_sock

        from src.utils.network import _detect_local_ip

        ip = _detect_local_ip()
        self.assertEqual(ip, "192.168.1.50")
        mock_sock.connect.assert_called_once_with(("8.8.8.8", 80))
        mock_sock.close.assert_called_once()

    @patch("src.utils.network.socket.socket")
    @patch("src.utils.network.socket.gethostbyname", return_value="10.0.0.5")
    @patch("src.utils.network.socket.gethostname", return_value="myhost")
    def test_fallback_to_hostname(self, mock_hostname, mock_resolve, mock_socket_cls):
        mock_socket_cls.return_value.connect.side_effect = OSError("no route")

        from src.utils.network import _detect_local_ip

        ip = _detect_local_ip()
        self.assertEqual(ip, "10.0.0.5")


if __name__ == "__main__":
    unittest.main()
