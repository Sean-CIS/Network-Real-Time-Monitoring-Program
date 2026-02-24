"""GeoIP lookup with MaxMind GeoLite2 database and caching."""

import ipaddress
import os

from src.utils import db

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
)
_DB_PATH = os.path.join(_DATA_DIR, "GeoLite2-City.mmdb")

_EMPTY_RESULT = {"country_code": "", "country_name": "", "city": ""}
_UNKNOWN_RESULT = {"country_code": "?", "country_name": "Unknown", "city": ""}


class GeoIPLookup:
    """GeoIP lookup using MaxMind GeoLite2 database with memory + DB caching."""

    def __init__(self):
        self._reader = None
        self._cache: dict[str, dict] = {}
        self._warned = False
        self._try_load_db()

    def _try_load_db(self):
        """Attempt to load the GeoLite2 database."""
        try:
            import geoip2.database
            if os.path.isfile(_DB_PATH):
                self._reader = geoip2.database.Reader(_DB_PATH)
            elif not self._warned:
                self._warned = True
                print(
                    f"[GeoIP] GeoLite2 database not found at {_DB_PATH}. "
                    "Download from https://dev.maxmind.com/geoip/geolite2-free-geolite2-databases. "
                    "GeoIP features disabled."
                )
        except ImportError:
            if not self._warned:
                self._warned = True
                print("[GeoIP] geoip2 package not installed. GeoIP features disabled.")

    @staticmethod
    def is_private(ip: str) -> bool:
        """Check if an IP address is private (RFC 1918, loopback, etc.)."""
        if not ip:
            return True
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    def lookup(self, ip: str) -> dict:
        """Look up GeoIP data for an IP address.

        Returns dict with keys: country_code, country_name, city.
        Returns empty strings for private IPs, '?' for unknown public IPs.
        """
        if not ip or self.is_private(ip):
            return _EMPTY_RESULT.copy()

        # Check memory cache
        if ip in self._cache:
            return self._cache[ip]

        # Check DB cache
        cached = db.get_geoip_cache(ip)
        if cached:
            result = {
                "country_code": cached.get("country_code", "?"),
                "country_name": cached.get("country_name", "Unknown"),
                "city": cached.get("city", ""),
            }
            self._cache[ip] = result
            return result

        # Look up in GeoLite2
        result = self._lookup_geoip(ip)
        self._cache[ip] = result
        db.upsert_geoip_cache(
            ip, result["country_code"], result["country_name"], result["city"]
        )
        return result

    def _lookup_geoip(self, ip: str) -> dict:
        """Perform actual GeoLite2 database lookup."""
        if not self._reader:
            return _UNKNOWN_RESULT.copy()
        try:
            resp = self._reader.city(ip)
            return {
                "country_code": resp.country.iso_code or "?",
                "country_name": resp.country.name or "Unknown",
                "city": resp.city.name or "",
            }
        except Exception:
            return _UNKNOWN_RESULT.copy()

    def lookup_batch(self, ips: list[str]) -> dict[str, dict]:
        """Look up GeoIP data for multiple IPs."""
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results

    def close(self):
        """Close the GeoIP database reader."""
        if self._reader:
            self._reader.close()
            self._reader = None
