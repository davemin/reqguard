from __future__ import annotations

import json
import socket
import time
from collections import deque
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


@lru_cache(maxsize=4096)
def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


class GeoIpLookup:
    def __init__(self, db_path: Path) -> None:
        self.reader = None
        if db_path.exists():
            try:
                import geoip2.database  # type: ignore[import-not-found]

                self.reader = geoip2.database.Reader(str(db_path))
            except Exception:
                self.reader = None

    @lru_cache(maxsize=4096)
    def country(self, ip: str) -> str | None:
        if not self.reader:
            return None
        try:
            response = self.reader.country(ip)
        except Exception:
            return None
        return response.country.iso_code or response.registered_country.iso_code


class CountryLookup:
    def __init__(self, db_path: Path, provider: str, cache_path: Path, ip_lookup_url: str) -> None:
        self.provider = provider
        self.local = GeoIpLookup(db_path)
        self.ipwhois = IpWhoIsLookup(cache_path, api_base=ip_lookup_url)

    def country(self, ip: str) -> str | None:
        if self.provider == "none":
            return None
        if self.provider in {"local", "auto"}:
            country = self.local.country(ip)
            if country or self.provider == "local":
                return country
        if self.provider in {"ipwhois", "auto"}:
            return self.ipwhois.country(ip)
        return None


class IpWhoIsLookup:
    CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
    NEGATIVE_CACHE_TTL_SECONDS = 60 * 60
    MIN_INTERVAL_SECONDS = 1.05
    MAX_REQUESTS_PER_MINUTE = 60
    PENDING = "Pending"
    ERROR = "Err"

    def __init__(self, cache_path: Path, api_base: str = "https://ipwho.is", timeout_seconds: float = 0.75) -> None:
        self.cache_path = cache_path
        self.api_base = api_base.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.cache = self._load_cache()
        self.last_request_at = 0.0
        self.request_times: deque[float] = deque()

    def country(self, ip: str) -> str | None:
        normalized = self._normalized_public_ip(ip)
        if not normalized:
            return None
        if self._has_valid_cache(normalized):
            return self._cached_country(normalized)
        if not self._can_request():
            return self.PENDING
        country = self._fetch_country(normalized)
        if not country:
            country = self.ERROR
        ttl = self.NEGATIVE_CACHE_TTL_SECONDS if country == self.ERROR else self.CACHE_TTL_SECONDS
        self.cache[normalized] = {"country": country, "expires_at": time.time() + ttl}
        self._save_cache()
        return country

    def _normalized_public_ip(self, ip: str) -> str | None:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return None
        if parsed.is_private or parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
            return None
        return str(parsed)

    def _cached_country(self, ip: str) -> str | None:
        item = self.cache.get(ip)
        country = item.get("country") if item else None
        return str(country) if country else None

    def _has_valid_cache(self, ip: str) -> bool:
        item = self.cache.get(ip)
        if not item:
            return False
        if float(item.get("expires_at", 0)) < time.time():
            self.cache.pop(ip, None)
            return False
        return True

    def _can_request(self) -> bool:
        now = time.monotonic()
        while self.request_times and now - self.request_times[0] >= 60:
            self.request_times.popleft()
        if now - self.last_request_at < self.MIN_INTERVAL_SECONDS:
            return False
        if len(self.request_times) >= self.MAX_REQUESTS_PER_MINUTE:
            return False
        self.last_request_at = now
        self.request_times.append(now)
        return True

    def _fetch_country(self, ip: str) -> str | None:
        url = f"{self.api_base}/{ip}?fields=success,country_code"
        try:
            with urlopen(url, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            return None
        if not payload.get("success", False):
            return None
        country = payload.get("country_code")
        return str(country) if country else None

    def _load_cache(self) -> dict[str, dict[str, object]]:
        if not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(key): value for key, value in data.items() if isinstance(value, dict)}

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.cache_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(self.cache, indent=2) + "\n", encoding="utf-8")
            tmp_path.replace(self.cache_path)
        except OSError:
            return
