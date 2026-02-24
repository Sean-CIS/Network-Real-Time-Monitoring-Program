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


class TestGatewayFromRoutePrint(unittest.TestCase):
    """Tests for Windows `route print` gateway detection."""

    ROUTE_PRINT_OUTPUT = (
        "===========================================================================\n"
        "Interface List\n"
        "===========================================================================\n"
        "\n"
        "IPv4 Route Table\n"
        "===========================================================================\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.105     25\n"
        "      192.168.0.0    255.255.255.0         On-link     192.168.0.105    281\n"
        "===========================================================================\n"
    )

    @patch("src.utils.network.subprocess.run")
    def test_parses_route_print_correctly(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=self.ROUTE_PRINT_OUTPUT)

        from src.utils.network import _gateway_from_route_print

        gw = _gateway_from_route_print()
        self.assertEqual(gw, "192.168.0.1")
        mock_run.assert_called_once_with(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5,
        )

    @patch("src.utils.network.subprocess.run")
    def test_route_print_no_default_route(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="IPv4 Route Table\nNo routes found.\n",
        )

        from src.utils.network import _gateway_from_route_print

        gw = _gateway_from_route_print()
        self.assertEqual(gw, "")

    @patch("src.utils.network.subprocess.run", side_effect=FileNotFoundError)
    def test_route_command_not_found(self, mock_run):
        from src.utils.network import _gateway_from_route_print

        gw = _gateway_from_route_print()
        self.assertEqual(gw, "")


class TestGatewayFromLocalIp(unittest.TestCase):
    """Tests for the last-resort gateway derivation from local IP."""

    @patch("src.utils.network._detect_local_ip", return_value="192.168.0.105")
    def test_derives_gateway_from_local_ip(self, mock_ip):
        from src.utils.network import _gateway_from_local_ip

        gw = _gateway_from_local_ip()
        self.assertEqual(gw, "192.168.0.1")

    @patch("src.utils.network._detect_local_ip", return_value="10.0.2.15")
    def test_derives_10_network_gateway(self, mock_ip):
        from src.utils.network import _gateway_from_local_ip

        gw = _gateway_from_local_ip()
        self.assertEqual(gw, "10.0.2.1")

    @patch("src.utils.network._detect_local_ip", return_value="127.0.0.1")
    def test_skips_localhost(self, mock_ip):
        from src.utils.network import _gateway_from_local_ip

        gw = _gateway_from_local_ip()
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
