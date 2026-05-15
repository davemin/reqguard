from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CountryStat:
    country: str
    count: int
    unique_ips: int
    banned_count: int = 0


@dataclass(frozen=True)
class TrafficStats:
    total: int
    live: int
    banned: int
    unique_ips: int
    persisted_bans: int
    countries: list[CountryStat]
    banned_countries: list[CountryStat]


def build_traffic_stats(
    observations: Iterable[tuple[str, str | None]],
    banned_ips: set[str],
    banned_countries: Iterable[str | None],
) -> TrafficStats:
    total = 0
    live = 0
    banned = 0
    unique_ips: set[str] = set()
    country_counts: Counter[str] = Counter()
    country_ips: dict[str, set[str]] = defaultdict(set)
    country_banned_counts: Counter[str] = Counter()

    for ip, country in observations:
        normalized_country = normalize_country(country)
        total += 1
        unique_ips.add(ip)
        country_counts[normalized_country] += 1
        country_ips[normalized_country].add(ip)
        if ip in banned_ips:
            banned += 1
            country_banned_counts[normalized_country] += 1
        else:
            live += 1

    banned_country_counts = Counter(normalize_country(country) for country in banned_countries)
    return TrafficStats(
        total=total,
        live=live,
        banned=banned,
        unique_ips=len(unique_ips),
        persisted_bans=sum(banned_country_counts.values()),
        countries=[
            CountryStat(
                country=country,
                count=count,
                unique_ips=len(country_ips[country]),
                banned_count=country_banned_counts[country],
            )
            for country, count in sorted(country_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        banned_countries=[
            CountryStat(country=country, count=count, unique_ips=count)
            for country, count in sorted(banned_country_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
    )


def normalize_country(country: str | None) -> str:
    return country or "--"
