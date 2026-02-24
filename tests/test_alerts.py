import unittest
from unittest.mock import patch


class TestAlertEngine(unittest.TestCase):
    @patch("src.core.alerts.db")
    def test_bandwidth_threshold_exceeded(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        engine.configure(bandwidth_mbps=10.0)

        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        # 20 MB/s = 160 Mbps, should trigger alert (threshold is 10 Mbps)
        data = {"eth0": {"speed_down": 20_000_000, "speed_up": 1000}}
        engine.check_bandwidth(data)
        self.assertGreater(len(triggered), 0)

    @patch("src.core.alerts.db")
    def test_bandwidth_below_threshold(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        engine.configure(bandwidth_mbps=100.0)

        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        # 100 KB/s = 0.8 Mbps, well below 100 Mbps threshold
        data = {"eth0": {"speed_down": 100_000, "speed_up": 50_000}}
        engine.check_bandwidth(data)
        self.assertEqual(len(triggered), 0)

    @patch("src.core.alerts.db")
    def test_latency_threshold_exceeded(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        engine.configure(latency_ms=100.0)

        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        results = [{"host": "8.8.8.8", "label": "Google", "latency_ms": 150.0, "is_alive": True}]
        engine.check_latency(results)
        self.assertGreater(len(triggered), 0)

    @patch("src.core.alerts.db")
    def test_host_unreachable_alert(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        results = [{"host": "10.0.0.1", "label": "Server", "latency_ms": None, "is_alive": False}]
        engine.check_latency(results)
        self.assertGreater(len(triggered), 0)
        self.assertIn("unreachable", triggered[0]["message"])

    @patch("src.core.alerts.db")
    def test_new_device_alert(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        devices = [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}]
        engine.check_devices(devices)
        self.assertGreater(len(triggered), 0)
        self.assertIn("New device", triggered[0]["message"])

    @patch("src.core.alerts.db")
    def test_known_device_no_alert(self, mock_db):
        from src.core.alerts import AlertEngine

        engine = AlertEngine()
        triggered = []
        engine.alert_triggered.connect(lambda a: triggered.append(a))

        devices = [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}]
        engine.check_devices(devices)  # First: new device alert
        triggered.clear()

        engine.check_devices(devices)  # Second: same device, no alert
        self.assertEqual(len(triggered), 0)


class TestConfigLoader(unittest.TestCase):
    def test_load_default_config(self):
        from src.utils.config import load_config
        config = load_config()
        self.assertIn("general", config)
        self.assertIn("bandwidth", config)
        self.assertIn("latency", config)
        self.assertIn("alerts", config)

    def test_get_config_value(self):
        from src.utils.config import load_config, get
        load_config()
        interval = get("general", "update_interval_ms", 1000)
        self.assertEqual(interval, 1000)

    def test_get_missing_key_returns_default(self):
        from src.utils.config import load_config, get
        load_config()
        result = get("nonexistent", "key", "fallback")
        self.assertEqual(result, "fallback")


class TestDatabase(unittest.TestCase):
    def test_init_db(self):
        from src.utils.db import init_db
        init_db()

    def test_insert_and_get_devices(self):
        from src.utils.db import init_db, upsert_device, get_all_devices
        init_db()
        upsert_device(ip="10.0.0.99", mac="aa:bb:cc:dd:ee:ff", hostname="test-host")
        devices = get_all_devices()
        ips = [d["ip"] for d in devices]
        self.assertIn("10.0.0.99", ips)


if __name__ == "__main__":
    unittest.main()
