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

        CREATE TABLE IF NOT EXISTS geoip_cache (
            ip TEXT PRIMARY KEY,
            lat REAL,
            lon REAL,
            country TEXT,
            country_code TEXT,
            city TEXT,
            isp TEXT,
            cached_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connection_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            protocol TEXT,
            status TEXT,
            pid INTEGER,
            process_name TEXT,
            country TEXT,
            city TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT,
            description TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            evidence TEXT,
            recommended_action TEXT
        );

        CREATE TABLE IF NOT EXISTS dns_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            query_name TEXT,
            query_type TEXT,
            response_ips TEXT,
            response_code TEXT,
            is_suspicious INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS flow_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            app_protocol TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_recv INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            duration_s REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_baseline (
            metric TEXT PRIMARY KEY,
            mean REAL DEFAULT 0,
            std_dev REAL DEFAULT 0,
            sample_count INTEGER DEFAULT 0,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS set_defense_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT,
            description TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            evidence TEXT,
            recommended_action TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_bandwidth_ts ON bandwidth_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_latency_ts ON latency_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_geoip_cached ON geoip_cache(cached_at);
        CREATE INDEX IF NOT EXISTS idx_connlog_ts ON connection_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_security_ts ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_flow_ts ON flow_summary(timestamp);
        CREATE INDEX IF NOT EXISTS idx_set_defense_ts ON set_defense_events(timestamp);
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


# ── GeoIP cache ──────────────────────────────────────────────

def get_cached_geoip(ip: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM geoip_cache WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def get_all_cached_geoip() -> dict[str, dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM geoip_cache").fetchall()
    return {r["ip"]: dict(r) for r in rows}


def upsert_geoip(ip: str, lat: float, lon: float, country: str,
                 country_code: str, city: str, isp: str):
    conn = get_connection()
    conn.execute(
        """INSERT INTO geoip_cache (ip, lat, lon, country, country_code, city, isp, cached_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
             lat=excluded.lat, lon=excluded.lon, country=excluded.country,
             country_code=excluded.country_code, city=excluded.city,
             isp=excluded.isp, cached_at=excluded.cached_at
        """,
        (ip, lat, lon, country, country_code, city, isp, datetime.now().isoformat()),
    )
    conn.commit()


def purge_expired_geoip(ttl_hours: int = 24):
    conn = get_connection()
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(hours=ttl_hours)).isoformat()
    conn.execute("DELETE FROM geoip_cache WHERE cached_at < ?", (cutoff,))
    conn.commit()


# ── Security Events ──────────────────────────────────────────

def insert_security_event(rule_id: str, severity: str, title: str = "",
                          description: str = "", src_ip: str = "", dst_ip: str = "",
                          src_port: int = None, dst_port: int = None,
                          evidence: str = "", recommended_action: str = ""):
    conn = get_connection()
    conn.execute(
        """INSERT INTO security_events
           (timestamp, rule_id, severity, title, description, src_ip, dst_ip,
            src_port, dst_port, evidence, recommended_action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.now().isoformat(), rule_id, severity, title, description,
         src_ip, dst_ip, src_port, dst_port, evidence, recommended_action),
    )
    conn.commit()


def get_recent_security_events(limit: int = 500) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── DNS Log ──────────────────────────────────────────────────

def insert_dns_log(src_ip: str, query_name: str, query_type: str = "",
                   response_ips: str = "", response_code: str = "",
                   is_suspicious: bool = False):
    conn = get_connection()
    conn.execute(
        """INSERT INTO dns_log
           (timestamp, src_ip, query_name, query_type, response_ips, response_code, is_suspicious)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (datetime.now().isoformat(), src_ip, query_name, query_type,
         response_ips, response_code, int(is_suspicious)),
    )
    conn.commit()


def get_recent_dns_logs(limit: int = 1000) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM dns_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_dns_stats() -> dict:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM dns_log").fetchone()[0]
    unique = conn.execute("SELECT COUNT(DISTINCT query_name) FROM dns_log").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM dns_log WHERE is_suspicious = 1").fetchone()[0]
    nx = conn.execute("SELECT COUNT(*) FROM dns_log WHERE response_code = 'NXDOMAIN'").fetchone()[0]
    return {"total": total, "unique_domains": unique, "suspicious": suspicious, "nx_domains": nx}


# ── Flow Summary ─────────────────────────────────────────────

def insert_flow_summary(src_ip: str, dst_ip: str, protocol: str = "",
                        app_protocol: str = "", bytes_sent: int = 0,
                        bytes_recv: int = 0, packets: int = 0, duration_s: float = 0):
    conn = get_connection()
    conn.execute(
        """INSERT INTO flow_summary
           (timestamp, src_ip, dst_ip, protocol, app_protocol, bytes_sent, bytes_recv, packets, duration_s)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.now().isoformat(), src_ip, dst_ip, protocol, app_protocol,
         bytes_sent, bytes_recv, packets, duration_s),
    )
    conn.commit()


# ── Traffic Baseline ─────────────────────────────────────────

def upsert_baseline(metric: str, mean: float, std_dev: float, sample_count: int):
    conn = get_connection()
    conn.execute(
        """INSERT INTO traffic_baseline (metric, mean, std_dev, sample_count, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(metric) DO UPDATE SET
             mean=excluded.mean, std_dev=excluded.std_dev,
             sample_count=excluded.sample_count, updated_at=excluded.updated_at
        """,
        (metric, mean, std_dev, sample_count, datetime.now().isoformat()),
    )
    conn.commit()


def get_baseline(metric: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM traffic_baseline WHERE metric = ?", (metric,)).fetchone()
    return dict(row) if row else None


# ── SET Defense Events ───────────────────────────────────────

def insert_set_defense_event(category: str, severity: str, title: str = "",
                             description: str = "", src_ip: str = "", dst_ip: str = "",
                             evidence: str = "", recommended_action: str = ""):
    conn = get_connection()
    conn.execute(
        """INSERT INTO set_defense_events
           (timestamp, category, severity, title, description, src_ip, dst_ip, evidence, recommended_action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.now().isoformat(), category, severity, title, description,
         src_ip, dst_ip, evidence, recommended_action),
    )
    conn.commit()


def get_recent_set_defense_events(limit: int = 500) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM set_defense_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]
