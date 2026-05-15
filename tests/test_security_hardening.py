from pathlib import Path

import pytest

import reqguard.firewall as firewall
from reqguard.config import (
    DEFAULT_BANS_FILE,
    DEFAULT_WEB_BAN_PORTS,
    Config,
    clean_env_value,
    default_file_values,
    normalize_ip_lookup_url,
    normalize_web_ban_ports,
)
from reqguard.enrich import IpWhoIsLookup


def test_default_file_values_parse_only_allowed_keys(tmp_path):
    config = Path(tmp_path) / "reqguard"
    config.write_text(
        "REQGUARD_FIREWALL_BACKEND=ufw\n"
        "REQGUARD_BANS_FILE=/var/lib/reqguard/bans.json\n"
        "REQGUARD_SORT='count-desc'\n"
        "REQGUARD_IP_LOOKUP_URL=http://127.0.0.1:8080/geo\n"
        "REQGUARD_WEB_BAN_PORTS=8080,8443\n"
        "MALICIOUS=$(touch /tmp/owned)\n",
        encoding="utf-8",
    )

    assert default_file_values(config) == {
        "REQGUARD_FIREWALL_BACKEND": "ufw",
        "REQGUARD_BANS_FILE": "/var/lib/reqguard/bans.json",
        "REQGUARD_SORT": "count-desc",
        "REQGUARD_IP_LOOKUP_URL": "http://127.0.0.1:8080/geo",
        "REQGUARD_WEB_BAN_PORTS": "8080,8443",
    }
    assert clean_env_value('"arrival"') == "arrival"


def test_refresh_seconds_is_clamped_to_minimum():
    assert Config(refresh_seconds=0.1).refresh_seconds == 1.2


def test_default_bans_file_path_is_configured_default():
    assert DEFAULT_BANS_FILE == Path("/var/lib/reqguard/bans.json")
    assert Config().bans_file == Path("/var/lib/reqguard/bans.json")


def test_ip_lookup_url_accepts_configurable_http_base_url():
    assert normalize_ip_lookup_url("http://127.0.0.1:8080/geo/") == "http://127.0.0.1:8080/geo"
    assert Config(ip_lookup_url="http://geo.internal").ip_lookup_url == "http://geo.internal"


def test_ip_lookup_url_falls_back_to_default_when_invalid():
    assert normalize_ip_lookup_url("file:///tmp/service") == "https://ipwho.is"
    assert normalize_ip_lookup_url("http://") == "https://ipwho.is"


def test_web_ban_ports_are_configurable_and_defaulted():
    assert normalize_web_ban_ports("8080,8443") == (8080, 8443)
    assert normalize_web_ban_ports("bad,0,70000") == DEFAULT_WEB_BAN_PORTS
    assert Config(web_ban_ports="8080,8443").web_ban_ports == (8080, 8443)


def test_ipwhois_returns_pending_when_rate_limited(tmp_path):
    lookup = IpWhoIsLookup(Path(tmp_path) / "cache.json")
    lookup._can_request = lambda: False

    assert lookup.country("8.8.8.8") == "Pending"


def test_ipwhois_returns_err_on_lookup_failure(tmp_path):
    lookup = IpWhoIsLookup(Path(tmp_path) / "cache.json")
    lookup._fetch_country = lambda ip: None

    assert lookup.country("8.8.8.8") == "Err"


def test_ufw_rule_numbers_match_exact_ip(monkeypatch):
    class Result:
        stdout = (
            "[ 1] Anywhere DENY IN 203.0.113.10 # reqguard\n"
            "[ 2] Anywhere DENY IN 203.0.113.1 # reqguard\n"
        )

    monkeypatch.setattr(firewall, "run_ufw", lambda args, check=True: Result())

    assert firewall.ufw_reqguard_rule_numbers("203.0.113.1") == [2]


def test_ufw_rule_numbers_can_match_port_scoped_rules(monkeypatch):
    class Result:
        stdout = (
            "[ 1] 80/tcp DENY IN 203.0.113.10 # reqguard\n"
            "[ 2] 443/tcp DENY IN 203.0.113.10 # reqguard\n"
        )

    monkeypatch.setattr(firewall, "run_ufw", lambda args, check=True: Result())

    assert firewall.ufw_reqguard_rule_numbers("203.0.113.10", ports=(80,)) == [1]


def test_ban_ufw_ip_uses_port_scoped_rules(monkeypatch):
    commands = []

    monkeypatch.setattr(firewall, "init_ufw", lambda: None)
    monkeypatch.setattr(firewall, "ufw_reqguard_rule_numbers", lambda ip, ports=None: [])
    monkeypatch.setattr(firewall, "run_ufw", lambda args, check=True: commands.append(args))

    firewall.ban_ufw_ip("203.0.113.10", ports=(80, 443))

    assert commands == [
        ["insert", "1", "deny", "from", "203.0.113.10", "to", "any", "port", "80", "proto", "tcp", "comment", "reqguard"],
        ["insert", "1", "deny", "from", "203.0.113.10", "to", "any", "port", "443", "proto", "tcp", "comment", "reqguard"],
    ]


def test_init_ufw_rejects_inactive(monkeypatch):
    class Result:
        stdout = "Status: inactive\n"

    monkeypatch.setattr(firewall, "run_ufw", lambda args, check=True: Result())

    with pytest.raises(firewall.FirewallError):
        firewall.init_ufw()


def test_resolve_backend_prefers_active_ufw(monkeypatch):
    monkeypatch.setattr(firewall, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall, "ufw_is_active", lambda: True)
    monkeypatch.setattr(firewall, "nft_available", lambda: False)

    assert firewall.resolve_backend("auto") == firewall.BACKEND_UFW


def test_resolve_backend_falls_back_to_nftables(monkeypatch):
    monkeypatch.setattr(firewall, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall, "ufw_is_active", lambda: False)
    monkeypatch.setattr(firewall, "nft_available", lambda: True)

    assert firewall.resolve_backend("auto") == firewall.BACKEND_NFTABLES
