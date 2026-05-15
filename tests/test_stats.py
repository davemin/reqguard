from reqguard.stats import build_traffic_stats


def test_build_traffic_stats_counts_live_banned_and_countries():
    stats = build_traffic_stats(
        observations=[
            ("203.0.113.9", "US"),
            ("203.0.113.9", "US"),
            ("198.51.100.2", "DE"),
            ("192.0.2.4", None),
        ],
        banned_ips={"203.0.113.9"},
        banned_countries=["US", "US", "DE"],
    )

    assert stats.total == 4
    assert stats.live == 2
    assert stats.banned == 2
    assert stats.unique_ips == 3
    assert stats.persisted_bans == 3
    assert [(item.country, item.count, item.unique_ips, item.banned_count) for item in stats.countries] == [
        ("US", 2, 1, 2),
        ("--", 1, 1, 0),
        ("DE", 1, 1, 0),
    ]
    assert [(item.country, item.count) for item in stats.banned_countries] == [
        ("US", 2),
        ("DE", 1),
    ]
