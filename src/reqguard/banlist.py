from __future__ import annotations

import json
from ipaddress import ip_address
from pathlib import Path

from .models import BanEntry


class BanList:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, BanEntry]:
        if not self.path.exists():
            return {}
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        entries: dict[str, BanEntry] = {}
        for item in data.get("bans", []):
            entry = BanEntry(
                ip=str(ip_address(item["ip"])),
                reason=str(item.get("reason", "")),
                created_at=str(item["created_at"]),
                ports=normalize_ports(item.get("ports", ())),
            )
            entries[entry.ip] = entry
        return entries

    def save(self, entries: dict[str, BanEntry]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "bans": [
                {
                    "ip": entry.ip,
                    "reason": entry.reason,
                    "created_at": entry.created_at,
                    "ports": list(entry.ports),
                }
                for entry in sorted(entries.values(), key=lambda item: item.ip)
            ]
        }
        tmp_path = self.path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        tmp_path.replace(self.path)

    def add(self, ip: str, reason: str = "", ports: tuple[int, ...] | list[int] | None = None) -> BanEntry:
        normalized = str(ip_address(ip))
        entries = self.load()
        entry = entries.get(normalized) or BanEntry.create(normalized, reason)
        next_ports = normalize_ports(ports) if ports is not None else entry.ports
        if reason or next_ports != entry.ports:
            entry = BanEntry(
                ip=entry.ip,
                reason=reason or entry.reason,
                created_at=entry.created_at,
                ports=next_ports,
            )
        entries[normalized] = entry
        self.save(entries)
        return entry

    def add_many(self, items: list[tuple[str, str, tuple[int, ...] | list[int] | None]]) -> list[BanEntry]:
        entries = self.load()
        added: list[BanEntry] = []
        for ip, reason, ports in items:
            normalized = str(ip_address(ip))
            entry = entries.get(normalized) or BanEntry.create(normalized, reason)
            next_ports = normalize_ports(ports) if ports is not None else entry.ports
            if reason or next_ports != entry.ports:
                entry = BanEntry(
                    ip=entry.ip,
                    reason=reason or entry.reason,
                    created_at=entry.created_at,
                    ports=next_ports,
                )
            entries[normalized] = entry
            added.append(entry)
        self.save(entries)
        return added

    def remove(self, ip: str) -> bool:
        normalized = str(ip_address(ip))
        entries = self.load()
        existed = normalized in entries
        entries.pop(normalized, None)
        self.save(entries)
        return existed

    def remove_many(self, ips: list[str]) -> int:
        entries = self.load()
        removed = 0
        for ip in ips:
            normalized = str(ip_address(ip))
            if normalized in entries:
                removed += 1
            entries.pop(normalized, None)
        self.save(entries)
        return removed

    def contains(self, ip: str) -> bool:
        try:
            normalized = str(ip_address(ip))
        except ValueError:
            return False
        return normalized in self.load()


def normalize_ports(value: object) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw_ports: list[object] = [part.strip() for part in value.split(",")]
    else:
        try:
            raw_ports = list(value)  # type: ignore[arg-type]
        except TypeError:
            return ()

    ports: list[int] = []
    for item in raw_ports:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return tuple(ports)
