import unittest


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
