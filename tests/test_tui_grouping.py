from pathlib import Path

import reqguard.tui as tui
from reqguard.config import Config
from reqguard.models import BanEntry, Connection


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


def test_monitor_ip_filter_accepts_wildcard_prefix():
    assert tui.connection_matches_filters(
        Connection("tcp", "10.0.0.5", 443, "192.189.10.20", 50001, "ESTABLISHED", "1"),
        tui.MonitorFilterState(ip="192.189.*"),
    )
    assert not tui.connection_matches_filters(
        Connection("tcp", "10.0.0.5", 443, "192.188.10.20", 50001, "ESTABLISHED", "1"),
        tui.MonitorFilterState(ip="192.189.*"),
    )


def test_monitor_hostname_and_port_filters_accept_wildcards():
    matching = Connection(
        "tcp",
        "10.0.0.5",
        443,
        "192.189.10.20",
        50001,
        "ESTABLISHED",
        "1",
        hostname="scanner.example.com",
    )
    wrong_host = Connection(
        "tcp",
        "10.0.0.5",
        443,
        "192.189.10.21",
        50002,
        "ESTABLISHED",
        "2",
        hostname="client.example.com",
    )
    wrong_port = Connection(
        "tcp",
        "10.0.0.5",
        8443,
        "192.189.10.22",
        50003,
        "ESTABLISHED",
        "3",
        hostname="scanner.example.com",
    )

    filters = tui.MonitorFilterState(hostname="scanner.*", port="44*")

    assert tui.connection_matches_filters(matching, filters)
    assert not tui.connection_matches_filters(wrong_host, filters)
    assert not tui.connection_matches_filters(wrong_port, filters)


def test_monitor_port_filter_is_exact_without_wildcard():
    assert tui.connection_matches_filters(
        Connection("tcp", "10.0.0.5", 80, "192.189.10.20", 50001, "ESTABLISHED", "1"),
        tui.MonitorFilterState(port="80"),
    )
    assert not tui.connection_matches_filters(
        Connection("tcp", "10.0.0.5", 8080, "192.189.10.20", 50001, "ESTABLISHED", "1"),
        tui.MonitorFilterState(port="80"),
    )


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


def test_monitor_search_filter_accepts_wildcard_patterns():
    groups = [
        tui.IpGroup(
            ip="192.189.10.20",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 443, "192.189.10.20", 50001, "ESTABLISHED", "1", observed_at=100)
            ],
        ),
        tui.IpGroup(
            ip="192.188.10.20",
            count=1,
            connections=[
                Connection("tcp", "10.0.0.5", 80, "192.188.10.20", 50002, "ESTABLISHED", "2", observed_at=200)
            ],
        ),
    ]

    filtered = tui.apply_monitor_group_filters(groups, tui.MonitorFilterState(search="192.189.*"))

    assert [group.ip for group in filtered] == ["192.189.10.20"]


def test_monitor_view_cycle_includes_stats(tmp_path):
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))

    app._toggle_view()
    assert app.view_mode == tui.VIEW_BANS
    app._toggle_view()
    assert app.view_mode == tui.VIEW_STATS
    app._toggle_view()
    assert app.view_mode == tui.VIEW_REQUESTS


def test_monitor_clear_filters_resets_every_filter(tmp_path):
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))
    app.filters = tui.MonitorFilterState(
        search="scanner",
        ip="203.0.113.9",
        hostname="scanner.*",
        port="44*",
        country="US",
        start_at=100,
        end_at=200,
        date_label="2026-05-15",
    )

    app._clear_filters()

    assert app.filters == tui.MonitorFilterState()
    assert app.message == "all filters cleared"


def test_monitor_shift_selection_extends_action_rows(tmp_path):
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))
    rows = [
        tui.IpGroup(ip="203.0.113.1", count=1, connections=[]),
        tui.IpGroup(ip="203.0.113.2", count=1, connections=[]),
        tui.IpGroup(ip="203.0.113.3", count=1, connections=[]),
    ]

    app._extend_selection(rows, 1)
    app._extend_selection(rows, 1)

    assert app.selected == 2
    assert app.selected_ips == {"203.0.113.1", "203.0.113.2", "203.0.113.3"}
    assert [row.ip for row in app._action_rows(rows, tui.IpGroup)] == [
        "203.0.113.1",
        "203.0.113.2",
        "203.0.113.3",
    ]


def test_monitor_action_rows_fall_back_to_current_row(tmp_path):
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))
    rows = [
        tui.BannedIpRow(BanEntry("203.0.113.1", "manual", "2026-05-17T10:00:00+00:00")),
        tui.BannedIpRow(BanEntry("203.0.113.2", "manual", "2026-05-17T10:01:00+00:00")),
    ]
    app.selected = 1

    assert [row.ip for row in app._action_rows(rows, tui.BannedIpRow)] == ["203.0.113.2"]


def test_monitor_bulk_ban_persists_each_selected_ip(tmp_path, monkeypatch):
    banned: list[str] = []
    monkeypatch.setattr(tui, "ban_ip", lambda ip, backend=None: banned.append(ip))
    monkeypatch.setattr(tui, "unban_ip", lambda ip, backend=None: None)
    app = tui.MonitorApp(Config(bans_file=Path(tmp_path) / "bans.json", reverse_dns=False))
    groups = [
        tui.IpGroup(ip="203.0.113.1", count=2, connections=[]),
        tui.IpGroup(ip="203.0.113.2", count=3, connections=[]),
    ]
    app.selected_ips = {group.ip for group in groups}

    app._ban_groups(groups)

    assert banned == ["203.0.113.1", "203.0.113.2"]
    assert set(app.banlist.load()) == {"203.0.113.1", "203.0.113.2"}
    assert app.selected_ips == set()
