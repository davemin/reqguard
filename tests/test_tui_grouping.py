from pathlib import Path

import reqguard.tui as tui
from reqguard.config import Config
from reqguard.models import Connection


def test_groups_are_sorted_by_arrival_by_default(tmp_path, monkeypatch):
    sample = [
        Connection(
            "tcp",
            "10.0.0.5",
            443,
            "198.51.100.2",
            50001,
            "ESTABLISHED",
            "1",
            observed_at=300,
            observed_time="2026-05-14 12:00:03",
        ),
        Connection(
            "tcp",
            "10.0.0.5",
            80,
            "203.0.113.9",
            50002,
            "ESTABLISHED",
            "2",
            observed_at=100,
            observed_time="2026-05-14 12:00:01",
        ),
        Connection(
            "tcp",
            "10.0.0.5",
            443,
            "203.0.113.9",
            50003,
            "ESTABLISHED",
            "3",
            observed_at=200,
            observed_time="2026-05-14 12:00:02",
        ),
    ]
    monkeypatch.setattr(tui, "read_connections", lambda: sample)
    monkeypatch.setattr(tui, "reverse_dns", lambda ip: None)

    app = tui.MonitorApp(
        Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False)
    )

    groups = app._groups()

    assert [group.ip for group in groups] == ["198.51.100.2", "203.0.113.9"]
    assert [group.count for group in groups] == [1, 2]
    assert groups[0].last_seen == "2026-05-14 12:00:03"


def test_groups_can_be_sorted_by_count_desc(tmp_path, monkeypatch):
    sample = [
        Connection("tcp", "10.0.0.5", 443, "198.51.100.2", 50001, "ESTABLISHED", "1", observed_at=300),
        Connection("tcp", "10.0.0.5", 80, "203.0.113.9", 50002, "ESTABLISHED", "2", observed_at=100),
        Connection("tcp", "10.0.0.5", 443, "203.0.113.9", 50003, "ESTABLISHED", "3", observed_at=200),
    ]
    monkeypatch.setattr(tui, "read_connections", lambda: sample)
    monkeypatch.setattr(tui, "reverse_dns", lambda ip: None)

    app = tui.MonitorApp(
        Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False, sort_mode="count-desc")
    )

    groups = app._groups()

    assert [group.ip for group in groups] == ["203.0.113.9", "198.51.100.2"]


def test_groups_can_be_sorted_by_count_asc(tmp_path, monkeypatch):
    sample = [
        Connection("tcp", "10.0.0.5", 443, "198.51.100.2", 50001, "ESTABLISHED", "1", observed_at=300),
        Connection("tcp", "10.0.0.5", 80, "203.0.113.9", 50002, "ESTABLISHED", "2", observed_at=100),
        Connection("tcp", "10.0.0.5", 443, "203.0.113.9", 50003, "ESTABLISHED", "3", observed_at=200),
    ]
    monkeypatch.setattr(tui, "read_connections", lambda: sample)
    monkeypatch.setattr(tui, "reverse_dns", lambda ip: None)

    app = tui.MonitorApp(
        Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False, sort_mode="count-asc")
    )

    groups = app._groups()

    assert [group.ip for group in groups] == ["198.51.100.2", "203.0.113.9"]


def test_banned_groups_are_not_forced_to_top_by_sorting():
    groups = [
        tui.IpGroup(
            ip="198.51.100.2",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 443, "198.51.100.2", 50001, "ESTABLISHED", "1", observed_at=300)
            ],
            banned=False,
        ),
        tui.IpGroup(
            ip="203.0.113.9",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 443, "203.0.113.9", 50002, "ESTABLISHED", "2", observed_at=100)
            ],
            banned=True,
        ),
    ]

    assert [group.ip for group in tui.sort_ip_groups(groups, "arrival")] == [
        "198.51.100.2",
        "203.0.113.9",
    ]


def test_monitor_filters_are_applied_before_grouping_counts(tmp_path, monkeypatch):
    sample = [
        Connection("tcp", "10.0.0.5", 443, "203.0.113.9", 50001, "ESTABLISHED", "1", observed_at=100),
        Connection("tcp", "10.0.0.5", 80, "203.0.113.9", 50002, "ESTABLISHED", "2", observed_at=200),
        Connection("tcp", "10.0.0.5", 443, "198.51.100.2", 50003, "ESTABLISHED", "3", observed_at=300),
    ]
    monkeypatch.setattr(tui, "read_connections", lambda: sample)
    monkeypatch.setattr(tui, "reverse_dns", lambda ip: None)
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))
    app.filters = tui.MonitorFilterState(ip="203.0.113.9", start_at=150)

    groups = app._groups()

    assert len(groups) == 1
    assert groups[0].ip == "203.0.113.9"
    assert groups[0].count == 1
    assert groups[0].services == "80"


def test_monitor_search_and_country_filters_match_group_fields():
    groups = [
        tui.IpGroup(
            ip="203.0.113.9",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 443, "203.0.113.9", 50001, "ESTABLISHED", "1", observed_at=100)
            ],
            country="US",
            hostname="scanner.example",
        ),
        tui.IpGroup(
            ip="198.51.100.2",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 80, "198.51.100.2", 50002, "ESTABLISHED", "2", observed_at=200)
            ],
            country="DE",
            hostname="client.example",
        ),
    ]

    filtered = tui.apply_monitor_group_filters(groups, tui.MonitorFilterState(search="scanner", country="US"))

    assert [group.ip for group in filtered] == ["203.0.113.9"]


def test_monitor_view_cycle_includes_stats(tmp_path):
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))

    app._toggle_view()
    assert app.view_mode == tui.VIEW_BANS
    app._toggle_view()
    assert app.view_mode == tui.VIEW_STATS
    app._toggle_view()
    assert app.view_mode == tui.VIEW_REQUESTS
