from pathlib import Path

import reqguard.web_tui as web_tui
from reqguard.web_tui import (
    VIEW_BANS,
    VIEW_REQUESTS,
    VIEW_STATS,
    WebFilterState,
    WebMonitorApp,
    apply_group_filters,
    build_web_groups,
    event_matches_filters,
    parse_date_range,
    sort_web_groups,
)
from reqguard.config import Config
from reqguard.models import BanEntry
from reqguard.weblog import WebGroup, WebLogReader, WebRequest, parse_log_line


def test_parse_nginx_combined_log_line():
    request = parse_log_line(
        '203.0.113.9 - - [14/May/2026:12:00:00 +0000] '
        '"POST /login HTTP/1.1" 401 123 "https://example.com/" "curl/8.0"'
    )

    assert request is not None
    assert request.ip == "203.0.113.9"
    assert request.method == "POST"
    assert request.path == "/login"
    assert request.status == "401"
    assert request.user_agent == "curl/8.0"
    assert request.observed_time == "2026-05-14 12:00:00"


def test_parse_json_log_line_with_headers_and_payload():
    request = parse_log_line(
        '{"remote_addr":"198.51.100.2","method":"POST","path":"/login",'
        '"status":403,"headers":{"x-forwarded-for":"198.51.100.2"},'
        '"request_body":"username=test"}'
    )

    assert request is not None
    assert request.ip == "198.51.100.2"
    assert request.path == "/login"
    assert request.headers == '{"x-forwarded-for": "198.51.100.2"}'
    assert request.payload == "username=test"
    assert request.observed_time != "-"


def test_parse_log_line_without_date_assigns_current_observed_time():
    request = parse_log_line('203.0.113.9 "GET /health HTTP/1.1" 200 2 "-" "curl/8.0"')

    assert request is not None
    assert request.ip == "203.0.113.9"
    assert request.path == "/health"
    assert request.observed_time != "-"


def test_log_reader_groups_by_ip(tmp_path):
    log_file = Path(tmp_path) / "access.log"
    log_file.write_text(
        '203.0.113.9 - - [14/May/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "ua"\n'
        '203.0.113.9 - - [14/May/2026:12:00:01 +0000] "POST /login HTTP/1.1" 401 20 "-" "ua"\n'
        '198.51.100.2 - - [14/May/2026:12:00:02 +0000] "GET /admin HTTP/1.1" 404 30 "-" "ua"\n',
        encoding="utf-8",
    )
    reader = WebLogReader(log_file)

    reader.poll()
    groups = reader.groups(set())

    assert [group.ip for group in groups] == ["198.51.100.2", "203.0.113.9"]
    assert [group.count for group in groups] == [1, 2]
    assert groups[0].last_seen == "2026-05-14 12:00:02"


def test_web_groups_can_be_sorted_by_count_modes():
    groups = [
        WebGroup(
            ip="198.51.100.2",
            count=1,
            requests=[WebRequest("198.51.100.2", "GET", "/", "HTTP/1.1", "200", observed_at=300)],
        ),
        WebGroup(
            ip="203.0.113.9",
            count=2,
            requests=[
                WebRequest("203.0.113.9", "GET", "/", "HTTP/1.1", "200", observed_at=100),
                WebRequest("203.0.113.9", "POST", "/login", "HTTP/1.1", "401", observed_at=200),
            ],
        ),
    ]

    assert [group.ip for group in sort_web_groups(groups, "arrival")] == [
        "198.51.100.2",
        "203.0.113.9",
    ]
    assert [group.ip for group in sort_web_groups(groups, "count-desc")] == [
        "203.0.113.9",
        "198.51.100.2",
    ]
    assert [group.ip for group in sort_web_groups(groups, "count-asc")] == [
        "198.51.100.2",
        "203.0.113.9",
    ]


def test_banned_groups_are_not_forced_to_top_by_sorting():
    groups = [
        WebGroup(
            ip="198.51.100.2",
            count=1,
            requests=[WebRequest("198.51.100.2", "GET", "/", "HTTP/1.1", "200", observed_at=300)],
            banned=False,
        ),
        WebGroup(
            ip="203.0.113.9",
            count=1,
            requests=[WebRequest("203.0.113.9", "GET", "/", "HTTP/1.1", "200", observed_at=100)],
            banned=True,
        ),
    ]

    assert [group.ip for group in sort_web_groups(groups, "arrival")] == [
        "198.51.100.2",
        "203.0.113.9",
    ]


def test_path_date_and_ip_filters_are_applied_before_grouping_counts():
    events = [
        WebRequest("203.0.113.9", "GET", "/", "HTTP/1.1", "200", observed_at=100),
        WebRequest("203.0.113.9", "POST", "/login", "HTTP/1.1", "401", observed_at=200),
        WebRequest("203.0.113.9", "POST", "/admin", "HTTP/1.1", "403", observed_at=250),
        WebRequest("198.51.100.2", "GET", "/admin", "HTTP/1.1", "404", observed_at=300),
    ]
    filters = WebFilterState(ip="203.0.113.9", path="/login", start_at=150)
    filtered_events = [event for event in events if event_matches_filters(event, filters)]
    groups = build_web_groups(filtered_events, set())

    assert len(groups) == 1
    assert groups[0].ip == "203.0.113.9"
    assert groups[0].count == 1
    assert groups[0].top_paths == "/login(1)"


def test_web_ip_and_path_filters_accept_wildcards():
    events = [
        WebRequest("192.189.1.10", "GET", "/api/v1/login", "HTTP/1.1", "200", observed_at=100),
        WebRequest("192.189.1.11", "GET", "/api/v1/logout", "HTTP/1.1", "200", observed_at=100),
        WebRequest("192.188.1.10", "GET", "/api/v1/login", "HTTP/1.1", "200", observed_at=100),
    ]
    filters = WebFilterState(ip="192.189.*", path="/api/*/login")

    filtered_events = [event for event in events if event_matches_filters(event, filters)]

    assert [(event.ip, event.path) for event in filtered_events] == [("192.189.1.10", "/api/v1/login")]


def test_search_and_country_filters_match_group_fields():
    groups = [
        WebGroup(
            ip="203.0.113.9",
            count=1,
            requests=[WebRequest("203.0.113.9", "GET", "/login", "HTTP/1.1", "401", observed_at=100)],
            country="US",
        ),
        WebGroup(
            ip="198.51.100.2",
            count=1,
            requests=[WebRequest("198.51.100.2", "GET", "/admin", "HTTP/1.1", "404", observed_at=200)],
            country="DE",
        ),
    ]

    filtered = apply_group_filters(groups, WebFilterState(search="login", country="US"))

    assert [group.ip for group in filtered] == ["203.0.113.9"]


def test_web_search_filter_accepts_wildcard_patterns():
    groups = [
        WebGroup(
            ip="192.189.1.10",
            count=1,
            requests=[WebRequest("192.189.1.10", "GET", "/login", "HTTP/1.1", "401", observed_at=100)],
        ),
        WebGroup(
            ip="192.188.1.10",
            count=1,
            requests=[WebRequest("192.188.1.10", "GET", "/admin", "HTTP/1.1", "404", observed_at=200)],
        ),
    ]

    filtered = apply_group_filters(groups, WebFilterState(search="192.189.*"))

    assert [group.ip for group in filtered] == ["192.189.1.10"]


def test_parse_date_range_accepts_start_and_end():
    start, end = parse_date_range("2026-05-15 01:00:00..2026-05-15 02:00:00")

    assert start is not None
    assert end is not None
    assert start < end


def test_web_monitor_view_cycle_includes_stats(tmp_path):
    app = WebMonitorApp(Config(bans_file=Path(tmp_path) / "bans.json"), log_file=Path(tmp_path) / "access.log")

    app._toggle_view()
    assert app.view_mode == VIEW_BANS
    app._toggle_view()
    assert app.view_mode == VIEW_STATS
    app._toggle_view()
    assert app.view_mode == VIEW_REQUESTS


def test_web_monitor_clear_filters_resets_path_ip_date_and_search(tmp_path):
    app = WebMonitorApp(Config(bans_file=Path(tmp_path) / "bans.json"), log_file=Path(tmp_path) / "access.log")
    app.filters = WebFilterState(
        search="login",
        ip="203.0.113.9",
        path="/login",
        country="US",
        start_at=100,
        end_at=200,
        date_label="2026-05-15",
    )

    app._clear_filters()

    assert app.filters == WebFilterState()
    assert app.message == "all filters cleared"


def test_web_monitor_shift_selection_extends_action_rows(tmp_path):
    app = WebMonitorApp(Config(bans_file=Path(tmp_path) / "bans.json"), log_file=Path(tmp_path) / "access.log")
    rows = [
        WebGroup(ip="203.0.113.1", count=1, requests=[]),
        WebGroup(ip="203.0.113.2", count=1, requests=[]),
        WebGroup(ip="203.0.113.3", count=1, requests=[]),
    ]

    app._extend_selection(rows, 1)
    app._extend_selection(rows, 1)

    assert app.selected == 2
    assert app.selected_ips == {"203.0.113.1", "203.0.113.2", "203.0.113.3"}
    assert [row.ip for row in app._action_rows(rows, WebGroup)] == [
        "203.0.113.1",
        "203.0.113.2",
        "203.0.113.3",
    ]


def test_web_monitor_action_rows_fall_back_to_current_ban_row(tmp_path):
    app = WebMonitorApp(Config(bans_file=Path(tmp_path) / "bans.json"), log_file=Path(tmp_path) / "access.log")
    rows = [
        web_tui.BannedWebRow(BanEntry("203.0.113.1", "manual", "2026-05-17T10:00:00+00:00")),
        web_tui.BannedWebRow(BanEntry("203.0.113.2", "manual", "2026-05-17T10:01:00+00:00")),
    ]
    app.selected = 1

    assert [row.ip for row in app._action_rows(rows, web_tui.BannedWebRow)] == ["203.0.113.2"]


def test_web_monitor_bulk_ban_uses_web_ports_and_persists_each_ip(tmp_path, monkeypatch):
    calls: list[tuple[str, tuple[int, ...] | None]] = []
    monkeypatch.setattr(
        web_tui,
        "ban_ip",
        lambda ip, backend=None, ports=None: calls.append((ip, ports)),
    )
    monkeypatch.setattr(web_tui, "unban_ip", lambda ip, backend=None, ports=None: None)
    app = WebMonitorApp(
        Config(bans_file=Path(tmp_path) / "bans.json", web_ban_ports=(8080, 8443)),
        log_file=Path(tmp_path) / "access.log",
    )
    groups = [
        WebGroup(ip="203.0.113.1", count=2, requests=[]),
        WebGroup(ip="203.0.113.2", count=3, requests=[]),
    ]
    app.selected_ips = {group.ip for group in groups}

    app._ban_groups(groups)

    assert calls == [("203.0.113.1", (8080, 8443)), ("203.0.113.2", (8080, 8443))]
    assert set(app.banlist.load()) == {"203.0.113.1", "203.0.113.2"}
    assert all(entry.ports == (8080, 8443) for entry in app.banlist.load().values())
    assert app.selected_ips == set()
