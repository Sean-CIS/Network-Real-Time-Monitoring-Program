"""GeoIP batch resolver with SQLite caching."""

import ipaddress
import json
from datetime import datetime, timedelta

import requests
from PySide6.QtCore import QThread, Signal

from src.utils import db
from src.utils.config import get


class GeoIPResolver(QThread):
    """Resolves batches of IPs to geographic locations via ip-api.com."""

    resolved = Signal(dict)  # {ip: {lat, lon, country, country_code, city, isp}}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pending_ips: set[str] = set()
        self._cache: dict[str, dict] = {}
        self._api_url = get("geoip", "api_url", "http://ip-api.com/batch")
        self._ttl_hours = get("geoip", "cache_ttl_hours", 24)
        self._running = False

    def load_cache(self):
        self._cache = db.get_all_cached_geoip()

    def get_cached(self, ip: str) -> dict | None:
        return self._cache.get(ip)

    def get_all_cached(self) -> dict[str, dict]:
        return dict(self._cache)

    def queue_ips(self, ips: set[str]):
        for ip in ips:
            if not self._is_public(ip):
                continue
            if ip in self._cache:
                cached = self._cache[ip]
                cached_at = cached.get("cached_at", "")
                if cached_at:
                    try:
                        ts = datetime.fromisoformat(cached_at)
                        if datetime.now() - ts < timedelta(hours=self._ttl_hours):
                            continue
                    except ValueError:
                        pass
            self._pending_ips.add(ip)

    def resolve_now(self):
        if not self._pending_ips:
            return
        if not self.isRunning():
            self.start()

    def run(self):
        self._running = True
        while self._pending_ips and self._running:
            batch = list(self._pending_ips)[:100]
            for ip in batch:
                self._pending_ips.discard(ip)

            results = self._batch_lookup(batch)
            if results:
                for ip, info in results.items():
                    self._cache[ip] = info
                    db.upsert_geoip(
                        ip=ip,
                        lat=info.get("lat", 0),
                        lon=info.get("lon", 0),
                        country=info.get("country", ""),
                        country_code=info.get("country_code", ""),
                        city=info.get("city", ""),
                        isp=info.get("isp", ""),
                    )
                self.resolved.emit(results)
        self._running = False

    def stop(self):
        self._running = False

    def _batch_lookup(self, ips: list[str]) -> dict[str, dict]:
        results = {}
        try:
            payload = [{"query": ip, "fields": "status,country,countryCode,city,lat,lon,isp,query"}
                       for ip in ips]
            resp = requests.post(self._api_url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    if entry.get("status") == "success":
                        ip = entry["query"]
                        results[ip] = {
                            "lat": entry.get("lat", 0),
                            "lon": entry.get("lon", 0),
                            "country": entry.get("country", ""),
                            "country_code": entry.get("countryCode", ""),
                            "city": entry.get("city", ""),
                            "isp": entry.get("isp", ""),
                            "cached_at": datetime.now().isoformat(),
                        }
        except Exception:
            # Fallback: try individual lookups
            for ip in ips[:5]:  # limit fallback to avoid rate limiting
                try:
                    r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp",
                                     timeout=5)
                    if r.status_code == 200:
                        d = r.json()
                        if d.get("status") == "success":
                            results[ip] = {
                                "lat": d.get("lat", 0),
                                "lon": d.get("lon", 0),
                                "country": d.get("country", ""),
                                "country_code": d.get("countryCode", ""),
                                "city": d.get("city", ""),
                                "isp": d.get("isp", ""),
                                "cached_at": datetime.now().isoformat(),
                            }
                except Exception:
                    continue
        return results

    @staticmethod
    def _is_public(ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_global
        except ValueError:
            return False
