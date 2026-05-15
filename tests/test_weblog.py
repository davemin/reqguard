from pathlib import Path

from reqguard.web_tui import WebFilterState, apply_group_filters, build_web_groups, event_matches_filters, parse_date_range, sort_web_groups
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


def test_date_and_ip_filters_are_applied_before_grouping_counts():
    events = [
        WebRequest("203.0.113.9", "GET", "/", "HTTP/1.1", "200", observed_at=100),
        WebRequest("203.0.113.9", "POST", "/login", "HTTP/1.1", "401", observed_at=200),
        WebRequest("198.51.100.2", "GET", "/admin", "HTTP/1.1", "404", observed_at=300),
    ]
    filters = WebFilterState(ip="203.0.113.9", start_at=150)
    filtered_events = [event for event in events if event_matches_filters(event, filters)]
    groups = build_web_groups(filtered_events, set())

    assert len(groups) == 1
    assert groups[0].ip == "203.0.113.9"
    assert groups[0].count == 1
    assert groups[0].top_paths == "/login(1)"


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


def test_parse_date_range_accepts_start_and_end():
    start, end = parse_date_range("2026-05-15 01:00:00..2026-05-15 02:00:00")

    assert start is not None
    assert end is not None
    assert start < end
