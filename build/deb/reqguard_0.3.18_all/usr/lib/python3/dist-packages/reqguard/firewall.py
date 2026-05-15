from __future__ import annotations

import shutil
import subprocess
from ipaddress import ip_address
from re import match, search

from .models import BanEntry


NFT_TABLE = "reqguard"
NFT_CHAIN = "input"
NFT_SET_V4 = "banned_ipv4"
NFT_SET_V6 = "banned_ipv6"
BACKEND_NFTABLES = "nftables"
BACKEND_UFW = "ufw"
BACKEND_AUTO = "auto"
VALID_BACKENDS = {BACKEND_AUTO, BACKEND_NFTABLES, BACKEND_UFW}


class FirewallError(RuntimeError):
    pass


def nft_available() -> bool:
    return shutil.which("nft") is not None


def ufw_available() -> bool:
    return shutil.which("ufw") is not None


def run_nft(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    if not nft_available():
        raise FirewallError("nft command not found. Install nftables first.")
    return subprocess.run(
        ["nft", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_ufw(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    if not ufw_available():
        raise FirewallError("ufw command not found. Install ufw first.")
    return subprocess.run(
        ["ufw", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def normalize_backend(backend: str | None) -> str:
    value = (backend or BACKEND_AUTO).lower()
    if value not in VALID_BACKENDS:
        raise FirewallError(f"unsupported firewall backend: {backend}")
    return value


def resolve_backend(backend: str | None = None) -> str:
    selected = normalize_backend(backend)
    if selected != BACKEND_AUTO:
        return selected
    if ufw_available() and ufw_is_active():
        return BACKEND_UFW
    if nft_available():
        return BACKEND_NFTABLES
    raise FirewallError(
        "no active firewall backend found. Enable ufw or install nftables, "
        "or set REQGUARD_FIREWALL_BACKEND explicitly."
    )


def ufw_is_active() -> bool:
    if not ufw_available():
        return False
    result = run_ufw(["status"], check=False)
    output = result.stdout.lower()
    return result.returncode == 0 and ("active" in output or "attivo" in output) and "inactive" not in output and "inattivo" not in output


def init_firewall(backend: str | None = None) -> None:
    selected = resolve_backend(backend)
    if selected == BACKEND_UFW:
        init_ufw()
        return
    init_nftables()


def init_nftables() -> None:
    commands = [
        ["add", "table", "inet", NFT_TABLE],
        [
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            NFT_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-100",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
        ["add", "set", "inet", NFT_TABLE, NFT_SET_V4, "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"],
        ["add", "set", "inet", NFT_TABLE, NFT_SET_V6, "{", "type", "ipv6_addr", ";", "flags", "interval", ";", "}"],
    ]
    for command in commands:
        run_nft(command, check=False)
    ensure_nft_drop_rules()
    verify_nftables()


def ensure_nft_drop_rules() -> None:
    result = run_nft(["list", "table", "inet", NFT_TABLE], check=False)
    output = result.stdout if result.returncode == 0 else ""
    if "ip saddr @banned_ipv4 drop" not in output:
        run_nft(["add", "rule", "inet", NFT_TABLE, NFT_CHAIN, "ip", "saddr", "@banned_ipv4", "drop"], check=False)
    if "ip6 saddr @banned_ipv6 drop" not in output:
        run_nft(["add", "rule", "inet", NFT_TABLE, NFT_CHAIN, "ip6", "saddr", "@banned_ipv6", "drop"], check=False)


def verify_nftables() -> None:
    result = run_nft(["list", "table", "inet", NFT_TABLE], check=True)
    output = result.stdout
    required = (NFT_CHAIN, NFT_SET_V4, NFT_SET_V6, "@banned_ipv4", "@banned_ipv6")
    missing = [item for item in required if item not in output]
    if missing:
        raise FirewallError(f"incomplete nftables reqguard table, missing: {', '.join(missing)}")


def init_ufw() -> None:
    result = run_ufw(["status"], check=True)
    output = result.stdout.lower()
    if "inactive" in output or "inattivo" in output:
        raise FirewallError("ufw is installed but inactive. Run: sudo ufw allow OpenSSH && sudo ufw enable")
    if "active" not in output and "attivo" not in output:
        raise FirewallError("unable to confirm ufw is active from `ufw status` output")


def _set_for_ip(ip: str) -> str:
    version = ip_address(ip).version
    return NFT_SET_V4 if version == 4 else NFT_SET_V6


def normalize_firewall_ports(ports: tuple[int, ...] | list[int] | None) -> tuple[int, ...]:
    if ports is None:
        return ()
    normalized: list[int] = []
    for item in ports:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in normalized:
            normalized.append(port)
    return tuple(normalized)


def ban_ip(ip: str, backend: str | None = None, ports: tuple[int, ...] | list[int] | None = None) -> None:
    normalized = str(ip_address(ip))
    normalized_ports = normalize_firewall_ports(ports)
    selected = resolve_backend(backend)
    if selected == BACKEND_UFW:
        ban_ufw_ip(normalized, ports=normalized_ports or None)
        return
    if normalized_ports:
        raise FirewallError("port-scoped bans are supported only with the ufw backend")
    init_nftables()
    result = run_nft(["add", "element", "inet", NFT_TABLE, _set_for_ip(normalized), "{", normalized, "}"], check=False)
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise FirewallError(result.stderr.strip() or f"unable to add nftables ban for {normalized}")


def unban_ip(ip: str, backend: str | None = None, ports: tuple[int, ...] | list[int] | None = None) -> None:
    normalized = str(ip_address(ip))
    normalized_ports = normalize_firewall_ports(ports)
    selected = resolve_backend(backend)
    if selected == BACKEND_UFW:
        unban_ufw_ip(normalized, ports=normalized_ports or None)
        return
    if normalized_ports:
        raise FirewallError("port-scoped unbans are supported only with the ufw backend")
    init_nftables()
    result = run_nft(["delete", "element", "inet", NFT_TABLE, _set_for_ip(normalized), "{", normalized, "}"], check=False)
    if result.returncode != 0 and "No such file or directory" not in result.stderr:
        raise FirewallError(result.stderr.strip() or f"unable to delete nftables ban for {normalized}")


def sync(entries: dict[str, BanEntry], backend: str | None = None) -> None:
    selected = resolve_backend(backend)
    if selected == BACKEND_UFW:
        sync_ufw(entries)
        return
    if any(entry.ports for entry in entries.values()):
        raise FirewallError("port-scoped persisted bans require the ufw backend")
    init_nftables()
    run_nft(["flush", "set", "inet", NFT_TABLE, NFT_SET_V4], check=True)
    run_nft(["flush", "set", "inet", NFT_TABLE, NFT_SET_V6], check=True)
    for entry in entries.values():
        ban_ip(entry.ip, backend=BACKEND_NFTABLES)


def ban_ufw_ip(ip: str, ports: tuple[int, ...] | list[int] | None = None) -> None:
    init_ufw()
    normalized_ports = normalize_firewall_ports(ports)
    if not normalized_ports:
        if ufw_reqguard_rule_numbers(ip):
            return
        run_ufw(
            ["insert", "1", "deny", "from", ip, "to", "any", "comment", "reqguard"],
            check=True,
        )
        return

    for port in normalized_ports:
        if ufw_reqguard_rule_numbers(ip, ports=(port,)):
            continue
        run_ufw(
            [
                "insert",
                "1",
                "deny",
                "from",
                ip,
                "to",
                "any",
                "port",
                str(port),
                "proto",
                "tcp",
                "comment",
                "reqguard",
            ],
            check=True,
        )


def unban_ufw_ip(ip: str, ports: tuple[int, ...] | list[int] | None = None) -> None:
    init_ufw()
    normalized_ports = normalize_firewall_ports(ports)
    for rule_number in reversed(ufw_reqguard_rule_numbers(ip, ports=normalized_ports or None)):
        run_ufw(["--force", "delete", str(rule_number)], check=False)


def sync_ufw(entries: dict[str, BanEntry]) -> None:
    init_ufw()
    wanted = {entry.ip for entry in entries.values()}
    for ip in sorted(existing_ufw_reqguard_ips() - wanted):
        unban_ufw_ip(ip)
    for entry in sorted(entries.values(), key=lambda item: item.ip):
        unban_ufw_ip(entry.ip)
        ban_ufw_ip(entry.ip, ports=entry.ports or None)


def existing_ufw_reqguard_ips() -> set[str]:
    result = run_ufw(["status", "numbered"], check=True)
    ips: set[str] = set()
    for line in result.stdout.splitlines():
        if "reqguard" not in line:
            continue
        ips.update(ips_from_ufw_rule(line))
    return ips


def ufw_reqguard_rule_numbers(ip: str, ports: tuple[int, ...] | list[int] | None = None) -> list[int]:
    normalized_ports = normalize_firewall_ports(ports)
    result = run_ufw(["status", "numbered"], check=True)
    numbers: list[int] = []
    for line in result.stdout.splitlines():
        parsed = match(r"^\[\s*(\d+)\]\s+(.*)$", line)
        if not parsed:
            continue
        rule_text = parsed.group(2)
        if "reqguard" in rule_text and ip in ips_from_ufw_rule(rule_text):
            if normalized_ports and not ufw_rule_matches_ports(rule_text, normalized_ports):
                continue
            numbers.append(int(parsed.group(1)))
    return numbers


def ufw_rule_matches_ports(rule_text: str, ports: tuple[int, ...]) -> bool:
    return any(search(rf"(^|\D){port}(/tcp)?(\D|$)", rule_text) is not None for port in ports)


def ips_from_ufw_rule(rule_text: str) -> set[str]:
    ips: set[str] = set()
    for token in rule_text.replace("[", " ").replace("]", " ").split():
        try:
            ips.add(str(ip_address(token.strip(",;"))))
        except ValueError:
            continue
    return ips
