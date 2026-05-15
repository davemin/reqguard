from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_STATE_DIR = Path("/var/lib/reqguard")
DEFAULT_BANS_FILE = DEFAULT_STATE_DIR / "bans.json"
DEFAULT_COUNTRY_CACHE_FILE = DEFAULT_STATE_DIR / "country-cache.json"
DEFAULT_GEOIP_DB = Path("/usr/share/GeoIP/GeoLite2-Country.mmdb")
DEFAULT_ENV_FILE = Path("/etc/default/reqguard")
DEFAULT_FIREWALL_BACKEND = "auto"
DEFAULT_SORT_MODE = "arrival"
DEFAULT_REFRESH_SECONDS = 1.2
MIN_REFRESH_SECONDS = 1.2
DEFAULT_COUNTRY_PROVIDER = "ipwhois"
DEFAULT_IP_LOOKUP_URL = "https://ipwho.is"
DEFAULT_WEB_BAN_PORTS = (80, 443)
VALID_SORT_MODES = {"arrival", "count-desc", "count-asc"}
VALID_COUNTRY_PROVIDERS = {"none", "local", "ipwhois", "auto"}
ALLOWED_ENV_KEYS = {
    "REQGUARD_BANS_FILE",
    "REQGUARD_COUNTRY_CACHE_FILE",
    "REQGUARD_COUNTRY_PROVIDER",
    "REQGUARD_GEOIP_DB",
    "REQGUARD_IP_LOOKUP_URL",
    "REQGUARD_REFRESH_SECONDS",
    "REQGUARD_REVERSE_DNS",
    "REQGUARD_FIREWALL_BACKEND",
    "REQGUARD_SORT",
    "REQGUARD_WEB_BAN_PORTS",
}


@dataclass(frozen=True)
class Config:
    bans_file: Path = DEFAULT_BANS_FILE
    country_cache_file: Path = DEFAULT_COUNTRY_CACHE_FILE
    country_provider: str = DEFAULT_COUNTRY_PROVIDER
    geoip_db: Path = DEFAULT_GEOIP_DB
    ip_lookup_url: str = DEFAULT_IP_LOOKUP_URL
    refresh_seconds: float = DEFAULT_REFRESH_SECONDS
    reverse_dns: bool = True
    firewall_backend: str = DEFAULT_FIREWALL_BACKEND
    sort_mode: str = DEFAULT_SORT_MODE
    web_ban_ports: tuple[int, ...] = DEFAULT_WEB_BAN_PORTS

    def __post_init__(self) -> None:
        object.__setattr__(self, "refresh_seconds", normalize_refresh_seconds(self.refresh_seconds))
        object.__setattr__(self, "country_provider", normalize_country_provider(self.country_provider))
        object.__setattr__(self, "ip_lookup_url", normalize_ip_lookup_url(self.ip_lookup_url))
        object.__setattr__(self, "sort_mode", normalize_sort_mode(self.sort_mode))
        object.__setattr__(self, "web_ban_ports", normalize_web_ban_ports(self.web_ban_ports))

    @classmethod
    def from_env(cls) -> "Config":
        values = default_file_values()
        values.update({key: value for key, value in os.environ.items() if key in ALLOWED_ENV_KEYS})
        bans_file = Path(values.get("REQGUARD_BANS_FILE", DEFAULT_BANS_FILE))
        country_cache_file = Path(values.get("REQGUARD_COUNTRY_CACHE_FILE", DEFAULT_COUNTRY_CACHE_FILE))
        country_provider = values.get("REQGUARD_COUNTRY_PROVIDER", DEFAULT_COUNTRY_PROVIDER)
        geoip_db = Path(values.get("REQGUARD_GEOIP_DB", DEFAULT_GEOIP_DB))
        ip_lookup_url = values.get("REQGUARD_IP_LOOKUP_URL", DEFAULT_IP_LOOKUP_URL)
        refresh_seconds = normalize_refresh_seconds(values.get("REQGUARD_REFRESH_SECONDS"))
        firewall_backend = values.get("REQGUARD_FIREWALL_BACKEND", DEFAULT_FIREWALL_BACKEND)
        sort_mode = values.get("REQGUARD_SORT", DEFAULT_SORT_MODE)
        web_ban_ports = values.get("REQGUARD_WEB_BAN_PORTS")
        reverse_dns = values.get("REQGUARD_REVERSE_DNS", "1").lower() not in {
            "0",
            "false",
            "no",
        }
        return cls(
            bans_file=bans_file,
            country_cache_file=country_cache_file,
            country_provider=normalize_country_provider(country_provider),
            geoip_db=geoip_db,
            ip_lookup_url=normalize_ip_lookup_url(ip_lookup_url),
            refresh_seconds=refresh_seconds,
            reverse_dns=reverse_dns,
            firewall_backend=firewall_backend,
            sort_mode=normalize_sort_mode(sort_mode),
            web_ban_ports=normalize_web_ban_ports(web_ban_ports),
        )


def normalize_sort_mode(sort_mode: str | None) -> str:
    value = (sort_mode or DEFAULT_SORT_MODE).lower()
    if value not in VALID_SORT_MODES:
        return DEFAULT_SORT_MODE
    return value


def normalize_country_provider(provider: str | None) -> str:
    value = (provider or DEFAULT_COUNTRY_PROVIDER).lower()
    if value not in VALID_COUNTRY_PROVIDERS:
        return DEFAULT_COUNTRY_PROVIDER
    return value


def normalize_refresh_seconds(value: str | float | None) -> float:
    try:
        seconds = float(value if value is not None else DEFAULT_REFRESH_SECONDS)
    except (TypeError, ValueError):
        seconds = DEFAULT_REFRESH_SECONDS
    return max(MIN_REFRESH_SECONDS, seconds)


def normalize_ip_lookup_url(value: str | None) -> str:
    cleaned = (value or DEFAULT_IP_LOOKUP_URL).strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return DEFAULT_IP_LOOKUP_URL
    return cleaned


def normalize_web_ban_ports(value: object) -> tuple[int, ...]:
    if value is None:
        return DEFAULT_WEB_BAN_PORTS
    raw_ports: list[str | int]
    if isinstance(value, str):
        raw_ports = [part.strip() for part in value.split(",")]
    else:
        try:
            raw_ports = list(value)  # type: ignore[arg-type]
        except TypeError:
            return DEFAULT_WEB_BAN_PORTS

    ports: list[int] = []
    for item in raw_ports:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return tuple(ports) if ports else DEFAULT_WEB_BAN_PORTS


def default_file_values(path: Path = DEFAULT_ENV_FILE) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key not in ALLOWED_ENV_KEYS:
            continue
        values[key] = clean_env_value(value)
    return values


def clean_env_value(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        cleaned = cleaned[1:-1]
    return cleaned
