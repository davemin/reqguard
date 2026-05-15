from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .banlist import BanList
from .config import Config, VALID_SORT_MODES, normalize_sort_mode
from .firewall import BACKEND_AUTO, BACKEND_NFTABLES, BACKEND_UFW, ban_ip, init_firewall, resolve_backend, sync, unban_ip
from .tui import run_monitor
from .web_tui import run_web_monitor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reqguard")
    parser.add_argument(
        "--bans-file",
        help="Path to persistent ban list. Default: /var/lib/reqguard/bans.json",
    )
    parser.add_argument(
        "--firewall-backend",
        choices=sorted([BACKEND_AUTO, BACKEND_NFTABLES, BACKEND_UFW]),
        help="Firewall backend to use. Default: REQGUARD_FIREWALL_BACKEND or auto.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor_parser = subparsers.add_parser("monitor", help="Open the TCP connection terminal monitor.")
    monitor_parser.add_argument(
        "--sort",
        choices=sorted(VALID_SORT_MODES),
        help="Sort mode: arrival, count-desc, or count-asc. Default: REQGUARD_SORT or arrival.",
    )
    web_monitor_parser = subparsers.add_parser("web-monitor", help="Open the HTTP access-log terminal monitor.")
    web_monitor_parser.add_argument("--log-file", help="Access log path. Defaults to nginx/apache access.log.")
    web_monitor_parser.add_argument("--max-events", type=int, default=1000, help="Maximum parsed requests kept in memory.")
    web_monitor_parser.add_argument(
        "--sort",
        choices=sorted(VALID_SORT_MODES),
        help="Sort mode: arrival, count-desc, or count-asc. Default: REQGUARD_SORT or arrival.",
    )
    subparsers.add_parser("init-firewall", help="Check/create firewall structures for the selected backend.")
    subparsers.add_parser("sync-firewall", help="Apply the persistent ban list to the selected firewall backend.")

    ban_parser = subparsers.add_parser("ban", help="Persist and apply an IP ban.")
    ban_parser.add_argument("ip")
    ban_parser.add_argument("--reason", default="")

    unban_parser = subparsers.add_parser("unban", help="Remove an IP ban.")
    unban_parser.add_argument("ip")

    subparsers.add_parser("bans", help="List persistent IP bans.")
    return parser


def config_from_args(args: argparse.Namespace) -> Config:
    config = Config.from_env()
    if args.bans_file:
        config = Config(
            bans_file=config.bans_file.__class__(args.bans_file),
            country_cache_file=config.country_cache_file,
            country_provider=config.country_provider,
            geoip_db=config.geoip_db,
            ip_lookup_url=config.ip_lookup_url,
            refresh_seconds=config.refresh_seconds,
            reverse_dns=config.reverse_dns,
            firewall_backend=config.firewall_backend,
            sort_mode=config.sort_mode,
            web_ban_ports=config.web_ban_ports,
        )
    if args.firewall_backend:
        config = Config(
            bans_file=config.bans_file,
            country_cache_file=config.country_cache_file,
            country_provider=config.country_provider,
            geoip_db=config.geoip_db,
            ip_lookup_url=config.ip_lookup_url,
            refresh_seconds=config.refresh_seconds,
            reverse_dns=config.reverse_dns,
            firewall_backend=args.firewall_backend,
            sort_mode=config.sort_mode,
            web_ban_ports=config.web_ban_ports,
        )
    if getattr(args, "sort", None):
        config = Config(
            bans_file=config.bans_file,
            country_cache_file=config.country_cache_file,
            country_provider=config.country_provider,
            geoip_db=config.geoip_db,
            ip_lookup_url=config.ip_lookup_url,
            refresh_seconds=config.refresh_seconds,
            reverse_dns=config.reverse_dns,
            firewall_backend=config.firewall_backend,
            sort_mode=normalize_sort_mode(args.sort),
            web_ban_ports=config.web_ban_ports,
        )
    return config


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = config_from_args(args)
    banlist = BanList(config.bans_file)

    try:
        if args.command == "monitor":
            run_monitor(config)
            return 0
        if args.command == "web-monitor":
            log_file = Path(args.log_file) if args.log_file else None
            run_web_monitor(config, log_file=log_file, max_events=args.max_events)
            return 0
        if args.command == "init-firewall":
            init_firewall(config.firewall_backend)
            print(f"reqguard firewall backend ready: {resolve_backend(config.firewall_backend)}")
            return 0
        if args.command == "sync-firewall":
            sync(banlist.load(), backend=config.firewall_backend)
            print(f"reqguard bans synchronized through {resolve_backend(config.firewall_backend)}")
            return 0
        if args.command == "ban":
            ban_ip(args.ip, backend=config.firewall_backend)
            try:
                entry = banlist.add(args.ip, args.reason)
            except Exception:
                unban_ip(args.ip, backend=config.firewall_backend)
                raise
            print(f"banned {entry.ip} through {resolve_backend(config.firewall_backend)}")
            return 0
        if args.command == "unban":
            unban_ip(args.ip, backend=config.firewall_backend)
            removed = banlist.remove(args.ip)
            print(f"unbanned {args.ip}" if removed else f"{args.ip} was not in the ban list")
            return 0
        if args.command == "bans":
            entries = banlist.load()
            if not entries:
                print("no bans")
                return 0
            for entry in entries.values():
                reason = f" reason={entry.reason}" if entry.reason else ""
                ports = f" ports={','.join(str(port) for port in entry.ports)}" if entry.ports else ""
                print(f"{entry.ip} created_at={entry.created_at}{ports}{reason}")
            return 0
    except PermissionError as exc:
        print(f"permission error: {exc}. Try running with sudo.", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
