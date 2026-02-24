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
        _local.conn.execute("PRAGMA synchronous=NORMAL")
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

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            description TEXT,
            raw_details TEXT
        );

        CREATE TABLE IF NOT EXISTS geoip_cache (
            ip TEXT PRIMARY KEY,
            country_code TEXT,
            country_name TEXT,
            city TEXT,
            looked_up_at TEXT
        );

        CREATE TABLE IF NOT EXISTS device_baseline (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            first_seen TEXT,
            is_trusted INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS dns_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            query TEXT NOT NULL,
            query_type TEXT,
            response TEXT,
            ttl INTEGER,
            source_ip TEXT
        );

        CREATE TABLE IF NOT EXISTS network_baseline (
            metric TEXT PRIMARY KEY,
            value_json TEXT,
            updated_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_bandwidth_ts ON bandwidth_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_latency_ts ON latency_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_secevt_ts ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_history(query);
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


def clear_alerts():
    """Delete all alerts from the database."""
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()


# ── Security Events ─────────────────────────────────────────


def insert_security_event(severity: str, event_type: str, description: str,
                          source_ip: str = "", dest_ip: str = "",
                          raw_details: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO security_events (timestamp, severity, event_type, source_ip, "
        "dest_ip, description, raw_details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), severity, event_type, source_ip, dest_ip,
         description, raw_details),
    )
    conn.commit()


def get_recent_security_events(limit: int = 200) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def clear_security_events():
    conn = get_connection()
    conn.execute("DELETE FROM security_events")
    conn.commit()


def get_security_event_counts_24h() -> dict:
    """Get security event counts grouped by hour for the last 24 hours."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT strftime('%H', timestamp) as hour,
                  severity,
                  COUNT(*) as cnt
           FROM security_events
           WHERE timestamp >= datetime('now', '-24 hours')
           GROUP BY hour, severity
           ORDER BY hour"""
    ).fetchall()
    # Build hourly dict
    hourly: dict[str, dict] = {}
    for r in rows:
        h = r["hour"]
        if h not in hourly:
            hourly[h] = {"hour": int(h), "critical": 0, "warning": 0, "info": 0}
        sev = r["severity"]
        if sev in hourly[h]:
            hourly[h][sev] = r["cnt"]
    return hourly


def get_security_event_total_counts() -> dict:
    """Get total security event counts by severity."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM security_events GROUP BY severity"
    ).fetchall()
    result = {"critical": 0, "warning": 0, "info": 0}
    for r in rows:
        if r["severity"] in result:
            result[r["severity"]] = r["cnt"]
    return result


# ── GeoIP Cache ─────────────────────────────────────────────


def upsert_geoip_cache(ip: str, country_code: str, country_name: str, city: str):
    conn = get_connection()
    conn.execute(
        """INSERT INTO geoip_cache (ip, country_code, country_name, city, looked_up_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
             country_code = excluded.country_code,
             country_name = excluded.country_name,
             city = excluded.city,
             looked_up_at = excluded.looked_up_at""",
        (ip, country_code, country_name, city, datetime.now().isoformat()),
    )
    conn.commit()


def get_geoip_cache(ip: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM geoip_cache WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


# ── Device Baseline ─────────────────────────────────────────


def get_baseline_devices() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM device_baseline").fetchall()
    return [dict(r) for r in rows]


def upsert_baseline_device(mac: str, ip: str = ""):
    conn = get_connection()
    conn.execute(
        """INSERT INTO device_baseline (mac, ip, first_seen, is_trusted)
           VALUES (?, ?, ?, 0)
           ON CONFLICT(mac) DO UPDATE SET ip = COALESCE(NULLIF(excluded.ip, ''), device_baseline.ip)""",
        (mac, ip, datetime.now().isoformat()),
    )
    conn.commit()


def mark_device_trusted(mac: str, trusted: bool = True):
    conn = get_connection()
    conn.execute(
        "UPDATE device_baseline SET is_trusted = ? WHERE mac = ?",
        (int(trusted), mac),
    )
    conn.commit()


def get_trusted_macs() -> set[str]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT mac FROM device_baseline WHERE is_trusted = 1"
    ).fetchall()
    return {r["mac"] for r in rows}


# ── DNS History ────────────────────────────────────────────


def insert_dns_record(query: str, query_type: str = "", response: str = "",
                      ttl: int = 0, source_ip: str = ""):
    if not query:
        return
    conn = get_connection()
    conn.execute(
        "INSERT INTO dns_history (timestamp, query, query_type, response, ttl, source_ip) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), query, query_type, response, ttl, source_ip),
    )
    conn.commit()


def get_recent_dns(limit: int = 500) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM dns_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def search_dns(query_filter: str, limit: int = 500) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM dns_history WHERE query LIKE ? ORDER BY timestamp DESC LIMIT ?",
        (f"%{query_filter}%", limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_dns_stats() -> dict:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM dns_history").fetchone()[0]
    unique = conn.execute("SELECT COUNT(DISTINCT query) FROM dns_history").fetchone()[0]
    nxdomain = conn.execute(
        "SELECT COUNT(*) FROM dns_history WHERE response = '' OR response IS NULL"
    ).fetchone()[0]
    return {"total": total, "unique_domains": unique, "nxdomain": nxdomain}


# ── Network Baseline ──────────────────────────────────────


def upsert_baseline_metric(metric: str, value_json: str):
    conn = get_connection()
    conn.execute(
        """INSERT INTO network_baseline (metric, value_json, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(metric) DO UPDATE SET
             value_json = excluded.value_json,
             updated_at = excluded.updated_at""",
        (metric, value_json, datetime.now().isoformat()),
    )
    conn.commit()


def get_baseline_metric(metric: str) -> Optional[str]:
    conn = get_connection()
    row = conn.execute(
        "SELECT value_json FROM network_baseline WHERE metric = ?", (metric,)
    ).fetchone()
    return row["value_json"] if row else None


# ── Bandwidth Heatmap ─────────────────────────────────────


def get_bandwidth_heatmap_data() -> list[dict]:
    """Get hourly bandwidth aggregated by day-of-week (0=Mon) and hour."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT
             CAST(strftime('%w', timestamp) AS INTEGER) as dow,
             CAST(strftime('%H', timestamp) AS INTEGER) as hour,
             AVG(speed_down + speed_up) as avg_bps
           FROM bandwidth_history
           WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY dow, hour
           ORDER BY dow, hour"""
    ).fetchall()
    return [dict(r) for r in rows]
