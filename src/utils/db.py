import os
import sqlite3
import threading
from datetime import datetime
from typing import Optional


_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "network_monitor.db",
)

_local = threading.local()


def get_connection() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(_DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            os_info TEXT,
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_online INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS bandwidth_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            interface TEXT NOT NULL,
            bytes_sent INTEGER,
            bytes_recv INTEGER,
            speed_up REAL,
            speed_down REAL
        );

        CREATE TABLE IF NOT EXISTS latency_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target TEXT NOT NULL,
            latency_ms REAL,
            is_alive INTEGER
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT,
            source TEXT,
            acknowledged INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            version TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_bandwidth_ts ON bandwidth_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_latency_ts ON latency_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
    """
    )
    conn.commit()


def insert_bandwidth(interface: str, bytes_sent: int, bytes_recv: int,
                     speed_up: float, speed_down: float):
    conn = get_connection()
    conn.execute(
        "INSERT INTO bandwidth_history (timestamp, interface, bytes_sent, bytes_recv, speed_up, speed_down) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), interface, bytes_sent, bytes_recv, speed_up, speed_down),
    )
    conn.commit()


def insert_latency(target: str, latency_ms: Optional[float], is_alive: bool):
    conn = get_connection()
    conn.execute(
        "INSERT INTO latency_history (timestamp, target, latency_ms, is_alive) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(), target, latency_ms, int(is_alive)),
    )
    conn.commit()


def insert_alert(alert_type: str, severity: str, message: str, source: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (timestamp, alert_type, severity, message, source) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), alert_type, severity, message, source),
    )
    conn.commit()


def upsert_device(ip: str, mac: str = "", hostname: str = "", os_info: str = "",
                  vendor: str = ""):
    conn = get_connection()
    now = datetime.now().isoformat()
    conn.execute(
        """INSERT INTO devices (ip, mac, hostname, os_info, vendor, first_seen, last_seen, is_online)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1)
           ON CONFLICT(ip) DO UPDATE SET
             mac = COALESCE(NULLIF(excluded.mac, ''), devices.mac),
             hostname = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
             os_info = COALESCE(NULLIF(excluded.os_info, ''), devices.os_info),
             vendor = COALESCE(NULLIF(excluded.vendor, ''), devices.vendor),
             last_seen = excluded.last_seen,
             is_online = 1
        """,
        (ip, mac, hostname, os_info, vendor, now, now),
    )
    conn.commit()


def get_all_devices() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


def get_recent_alerts(limit: int = 100) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]
