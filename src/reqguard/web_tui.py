from __future__ import annotations

import curses
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from .banlist import BanList
from .config import Config
from .enrich import CountryLookup
from .firewall import ban_ip, unban_ip
from .models import BanEntry
from .text import safe_terminal_text
from .viewport import scroll_start_index
from .weblog import WebGroup, WebLogReader, WebRequest, default_log_file, parse_datetime


TITLE = "Reqguard web request monitor"
HELP = "v/Tab view | / search | i IP | d date range | c country | x clear | s sort | b ban | u unban | q quit"
DETAIL_COLUMNS = "    Seen                Method Path                                             Status  Host/User-Agent"
SORT_MODES = ("arrival", "count-desc", "count-asc")
VIEW_REQUESTS = "requests"
VIEW_BANS = "bans"

COLOR_HEADER = 1
COLOR_LIVE = 2
COLOR_BANNED = 3
COLOR_DETAIL = 4
COLOR_STATUS = 5
COLOR_ERROR = 6


@dataclass(frozen=True)
class WebFilterState:
    search: str = ""
    ip: str = ""
    country: str = ""
    start_at: float | None = None
    end_at: float | None = None
    date_label: str = ""


@dataclass(frozen=True)
class BannedWebRow:
    entry: BanEntry
    group: WebGroup | None = None
    cached_country: str | None = None

    @property
    def ip(self) -> str:
        return self.entry.ip

    @property
    def created_at(self) -> str:
        return self.entry.created_at

    @property
    def reason(self) -> str:
        return self.entry.reason or "-"

    @property
    def country(self) -> str | None:
        return self.group.country if self.group else self.cached_country

    @property
    def count(self) -> int:
        return self.group.count if self.group else 0

    @property
    def last_seen(self) -> str:
        return self.group.last_seen if self.group else "-"

    @property
    def latest_status(self) -> str:
        return self.group.latest_status if self.group else "-"

    @property
    def top_paths(self) -> str:
        return self.group.top_paths if self.group else "-"


class WebMonitorApp:
    def __init__(self, config: Config, log_file: Path | None = None, max_events: int = 1000) -> None:
        self.config = config
        self.banlist = BanList(config.bans_file)
        self.log_file = log_file or default_log_file()
        self.reader = WebLogReader(self.log_file, max_events=max_events)
        self.country_lookup = CountryLookup(
            config.geoip_db,
            config.country_provider,
            config.country_cache_file,
            config.ip_lookup_url,
        )
        self.sort_mode = config.sort_mode
        self.view_mode = VIEW_REQUESTS
        self.filters = WebFilterState()
        self.selected = 0
        self.expanded: set[str] = set()
        self.message = ""

    def run(self) -> None:
        try:
            curses.wrapper(self._run)
        except KeyboardInterrupt:
            return

    def _run(self, stdscr: curses.window) -> None:
        curses.curs_set(0)
        self._setup_colors()
        stdscr.nodelay(True)
        stdscr.timeout(150)
        last_refresh = 0.0
        last_refresh_time = "-"
        groups: list[WebGroup] = []
        banned_rows: list[BannedWebRow] = []
        visible_rows: list[WebGroup | BannedWebRow] = []
        while True:
            now = time.monotonic()
            if now - last_refresh >= self.config.refresh_seconds:
                self.reader.wait_for_file(0)
                self.reader.poll()
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
                last_refresh = now
                last_refresh_time = current_display_time()
            self._draw(stdscr, groups, banned_rows, visible_rows, last_refresh_time)
            key = stdscr.getch()
            if key in {ord("q"), ord("Q")}:
                break
            if key == curses.KEY_UP:
                self.selected = max(0, self.selected - 1)
            elif key == curses.KEY_DOWN:
                self.selected = min(max(len(visible_rows) - 1, 0), self.selected + 1)
            elif key in {curses.KEY_ENTER, 10, 13, ord(" ")} and visible_rows:
                self._toggle(visible_rows[self.selected].ip)
            elif key in {9, ord("v"), ord("V")}:
                self._toggle_view()
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key == ord("/"):
                self._set_search(stdscr)
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("i"), ord("I")}:
                self._set_ip_filter(stdscr)
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("c"), ord("C")}:
                self._set_country_filter(stdscr)
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("d"), ord("D")}:
                self._set_date_filter(stdscr)
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("x"), ord("X")}:
                self.filters = WebFilterState()
                self.message = "filters cleared"
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("s"), ord("S")}:
                self._cycle_sort()
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("r"), ord("R")}:
                last_refresh = 0.0
            elif key in {ord("b"), ord("B")} and visible_rows and self.view_mode == VIEW_REQUESTS:
                self._ban(visible_rows[self.selected])
                last_refresh = 0.0
            elif key in {ord("u"), ord("U")} and visible_rows and self.view_mode == VIEW_BANS:
                self._unban_ip(visible_rows[self.selected].ip)
                last_refresh = 0.0

    def _groups(self) -> list[WebGroup]:
        banned_ips = set(self.banlist.load())
        events = [event for event in self.reader.events if event_matches_filters(event, self.filters)]
        groups = build_web_groups(events, banned_ips)
        groups = [
            replace(group, country=self.country_lookup.country(group.ip))
            for group in groups
        ]
        groups = apply_group_filters(groups, self.filters)
        return sort_web_groups(groups, self.sort_mode)

    def _banned_rows(self, groups: list[WebGroup]) -> list[BannedWebRow]:
        group_by_ip = {group.ip: group for group in groups}
        rows = [
            BannedWebRow(
                entry=entry,
                group=group_by_ip.get(entry.ip),
                cached_country=self.country_lookup.country(entry.ip),
            )
            for entry in self.banlist.load().values()
        ]
        rows = [row for row in rows if banned_row_matches_filters(row, self.filters)]
        return sorted(rows, key=lambda row: (-(row.group.last_seen_at if row.group else 0), row.ip))

    def _visible_rows(self, groups: list[WebGroup], banned_rows: list[BannedWebRow]) -> list[WebGroup | BannedWebRow]:
        if self.view_mode == VIEW_BANS:
            return banned_rows
        return [group for group in groups if not group.banned]

    def _toggle(self, ip: str) -> None:
        if ip in self.expanded:
            self.expanded.remove(ip)
        else:
            self.expanded.add(ip)

    def _cycle_sort(self) -> None:
        index = SORT_MODES.index(self.sort_mode) if self.sort_mode in SORT_MODES else 0
        self.sort_mode = SORT_MODES[(index + 1) % len(SORT_MODES)]
        self.message = f"sort changed to {self.sort_mode}"

    def _toggle_view(self) -> None:
        self.view_mode = VIEW_BANS if self.view_mode == VIEW_REQUESTS else VIEW_REQUESTS
        self.selected = 0
        self.message = f"view changed to {self.view_mode}"

    def _set_search(self, stdscr: curses.window) -> None:
        value = self._prompt(stdscr, "Search IP/date/top path (empty clears): ")
        self.filters = replace(self.filters, search=value)
        self.message = f"search set to {value}" if value else "search cleared"

    def _set_ip_filter(self, stdscr: curses.window) -> None:
        value = self._prompt(stdscr, "Filter exact IP (empty clears): ")
        self.filters = replace(self.filters, ip=value)
        self.message = f"IP filter set to {value}" if value else "IP filter cleared"

    def _set_country_filter(self, stdscr: curses.window) -> None:
        value = self._prompt(stdscr, "Filter country code, e.g. US (empty clears): ").upper()
        self.filters = replace(self.filters, country=value)
        self.message = f"country filter set to {value}" if value else "country filter cleared"

    def _set_date_filter(self, stdscr: curses.window) -> None:
        value = self._prompt(stdscr, "Date range start..end, YYYY-MM-DD HH:MM:SS (empty clears): ")
        if not value:
            self.filters = replace(self.filters, start_at=None, end_at=None, date_label="")
            self.message = "date filter cleared"
            return
        start_at, end_at = parse_date_range(value)
        if start_at is None and end_at is None:
            self.message = "invalid date range"
            return
        self.filters = replace(self.filters, start_at=start_at, end_at=end_at, date_label=value)
        self.message = f"date filter set to {value}"

    def _prompt(self, stdscr: curses.window, prompt: str) -> str:
        height, width = stdscr.getmaxyx()
        curses.curs_set(1)
        curses.echo()
        stdscr.nodelay(False)
        stdscr.move(height - 1, 0)
        stdscr.clrtoeol()
        stdscr.addnstr(height - 1, 0, prompt, width - 1, curses.A_REVERSE)
        try:
            raw = stdscr.getstr(height - 1, min(len(prompt), width - 2), max(1, width - len(prompt) - 1))
        finally:
            curses.noecho()
            curses.curs_set(0)
            stdscr.nodelay(True)
        return raw.decode("utf-8", errors="replace").strip()

    def _ban(self, group: WebGroup) -> None:
        ports = self.config.web_ban_ports
        try:
            ban_ip(group.ip, backend=self.config.firewall_backend, ports=ports)
            try:
                self.banlist.add(group.ip, reason=f"manual from web-monitor count={group.count}", ports=ports)
            except Exception:
                unban_ip(group.ip, backend=self.config.firewall_backend, ports=ports)
                raise
            self.message = f"banned {group.ip} on ports {','.join(str(port) for port in ports)}"
        except Exception as exc:
            self.message = f"ban failed: {exc}"

    def _unban_ip(self, ip: str) -> None:
        try:
            entry = self.banlist.load().get(ip)
            unban_ip(ip, backend=self.config.firewall_backend, ports=entry.ports if entry else None)
            self.banlist.remove(ip)
            self.message = f"unbanned {ip}"
        except Exception as exc:
            self.message = f"unban failed: {exc}"

    def _draw(
        self,
        stdscr: curses.window,
        groups: list[WebGroup],
        banned_rows: list[BannedWebRow],
        visible_rows: list[WebGroup | BannedWebRow],
        last_refresh_time: str,
    ) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 8 or width < 82:
            stdscr.addnstr(0, 0, "Terminal too small for web monitor. Resize to at least 82x8.", width - 1)
            stdscr.refresh()
            return
        selected_row = visible_rows[self.selected] if visible_rows else None
        visible_ip_count = len(visible_rows)
        visible_total_requests = sum(item.count for item in visible_rows)
        self._draw_header(stdscr, width, visible_ip_count, visible_total_requests, len(banned_rows), last_refresh_time)
        if self.message:
            attr = self._color(COLOR_ERROR if "failed" in self.message else COLOR_STATUS)
            stdscr.addnstr(2, 0, f"Last action: {safe_terminal_text(self.message)}", width - 1, attr)
        else:
            stdscr.addnstr(2, 0, f"Log: {safe_terminal_text(self.log_file)}", width - 1, self._color(COLOR_DETAIL))
        stdscr.addnstr(3, 0, self._filter_summary().ljust(width - 1), width - 1, self._color(COLOR_DETAIL))

        columns = (
            "Status  Last seen           IP remoto          Country   Req   Response Code  Top path"
            if self.view_mode == VIEW_REQUESTS
            else "Created at                 IP remoto          Country   Req   Response Code  Top path / Reason"
        )
        stdscr.addnstr(4, 0, columns, width - 1, curses.A_BOLD)
        stdscr.hline(5, 0, curses.ACS_HLINE, width - 1)

        list_bottom = max(6, height - 5)
        row_heights = [self._display_row_height(item) for item in visible_rows]
        start_index = scroll_start_index(row_heights, self.selected, list_bottom - 6)
        row = 6
        for idx, item in enumerate(visible_rows[start_index:], start=start_index):
            if row >= list_bottom:
                break
            if isinstance(item, BannedWebRow):
                attr = self._banned_row_attr(idx == self.selected)
                marker = "-" if item.ip in self.expanded else "+"
                line = (
                    f"{marker} {safe_terminal_text(item.created_at):<24.24} {item.ip:<18} "
                    f"{safe_terminal_text(item.country or '--'):<8} {item.count:<5} "
                    f"{safe_terminal_text(item.latest_status):<5} {safe_terminal_text(item.top_paths if item.group else item.reason):<90.90}"
                )
            else:
                attr = self._group_attr(item, idx == self.selected)
                marker = "-" if item.ip in self.expanded else "+"
                line = (
                    f"LIVE   {marker} {item.last_seen:<19} {item.ip:<18} {safe_terminal_text(item.country or '--'):<8} {item.count:<5} "
                    f"{safe_terminal_text(item.latest_status):<5} {safe_terminal_text(item.top_paths or '-'):<80.80}"
                )
            stdscr.addnstr(row, 0, line, width - 1, attr)
            row += 1
            detail_group = item.group if isinstance(item, BannedWebRow) else item
            if item.ip in self.expanded and detail_group:
                row = self._draw_group_details(stdscr, row, width, list_bottom, detail_group)
        self._draw_selected_summary(stdscr, height, width, selected_row)
        stdscr.refresh()

    def _display_row_height(self, item: WebGroup | BannedWebRow) -> int:
        detail_group = item.group if isinstance(item, BannedWebRow) else item
        if item.ip not in self.expanded or not detail_group:
            return 1

        detail_rows = 1
        for request in detail_group.requests[:20]:
            detail_rows += 1
            if request.headers != "-":
                detail_rows += 1
            if request.payload != "-":
                detail_rows += 1
        return 1 + detail_rows

    def _draw_group_details(
        self,
        stdscr: curses.window,
        row: int,
        width: int,
        height: int,
        group: WebGroup,
    ) -> int:
        if row < height:
            stdscr.addnstr(row, 0, DETAIL_COLUMNS, width - 1, curses.A_DIM)
            row += 1
        for request in group.requests[:20]:
            if row >= height:
                break
            host = safe_terminal_text(request.host if request.host != "-" else request.user_agent)
            line = (
                f"    {request.observed_time:<19} {safe_terminal_text(request.method):<6} "
                f"{safe_terminal_text(request.path):<48.48} {safe_terminal_text(request.status):<7} {host:<50.50}"
            )
            stdscr.addnstr(row, 0, line, width - 1, self._color(COLOR_DETAIL))
            row += 1
            if request.headers != "-" and row < height:
                headers = safe_terminal_text(request.headers)
                stdscr.addnstr(row, 0, f"      headers: {headers:<90.90}", width - 1, self._color(COLOR_DETAIL))
                row += 1
            if request.payload != "-" and row < height:
                payload = safe_terminal_text(request.payload)
                stdscr.addnstr(row, 0, f"      payload: {payload:<90.90}", width - 1, self._color(COLOR_DETAIL))
                row += 1
        return row

    def _draw_header(
        self,
        stdscr: curses.window,
        width: int,
        ip_count: int,
        total_requests: int,
        banned_count: int,
        last_refresh_time: str,
    ) -> None:
        stdscr.addnstr(0, 0, f" {TITLE} ".ljust(width - 1), width - 1, self._color(COLOR_HEADER) | curses.A_BOLD)
        stats = (
            f"View: {self.view_mode}   IPs shown: {ip_count}   HTTP requests shown: {total_requests}   "
            f"Persisted bans shown: {banned_count}/{len(self.banlist.load())}   Sort: {self.sort_mode}   "
            f"Last refresh: {last_refresh_time}"
        )
        stdscr.addnstr(1, 0, stats, width - 1, self._color(COLOR_STATUS))

    def _filter_summary(self) -> str:
        parts = []
        if self.filters.search:
            parts.append(f"search={self.filters.search}")
        if self.filters.ip:
            parts.append(f"ip={self.filters.ip}")
        if self.filters.country:
            parts.append(f"country={self.filters.country}")
        if self.filters.date_label:
            parts.append(f"date={self.filters.date_label}")
        return "Filters: " + (", ".join(parts) if parts else "none")

    def _draw_selected_summary(
        self,
        stdscr: curses.window,
        height: int,
        width: int,
        item: WebGroup | BannedWebRow | None,
    ) -> None:
        top = height - 4
        stdscr.hline(top, 0, curses.ACS_HLINE, width - 1)
        if not item:
            message = f"No rows in {self.view_mode} view. Waiting for log file or adjust filters: {self.log_file}"
            stdscr.addnstr(top + 1, 0, message, width - 1)
        elif isinstance(item, BannedWebRow):
            expanded = "expanded" if item.ip in self.expanded else "collapsed"
            summary = (
                f"Selected ban: {item.ip}   Created: {item.created_at}   Requests in filters: {item.count}   "
                f"Country: {item.country or '--'}   View: {expanded}"
            )
            stdscr.addnstr(top + 1, 0, summary, width - 1, self._color(COLOR_BANNED))
            detail = f"Reason: {safe_terminal_text(item.reason)}"
            stdscr.addnstr(top + 2, 0, detail, width - 1, self._color(COLOR_DETAIL))
        else:
            expanded = "expanded" if item.ip in self.expanded else "collapsed"
            summary = (
                f"Selected: {item.ip} [LIVE]   Requests: {item.count}   "
                f"Last seen: {item.last_seen}   Country: {item.country or '--'}   View: {expanded}"
            )
            stdscr.addnstr(top + 1, 0, summary, width - 1, self._group_attr(item, False))
            detail = f"Latest user-agent: {safe_terminal_text(item.latest_user_agent)}"
            stdscr.addnstr(top + 2, 0, detail, width - 1, self._color(COLOR_DETAIL))
        stdscr.addnstr(height - 1, 0, HELP.ljust(width - 1), width - 1, curses.A_REVERSE)

    def _setup_colors(self) -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(COLOR_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(COLOR_LIVE, curses.COLOR_GREEN, -1)
        curses.init_pair(COLOR_BANNED, curses.COLOR_RED, -1)
        curses.init_pair(COLOR_DETAIL, curses.COLOR_BLUE, -1)
        curses.init_pair(COLOR_STATUS, curses.COLOR_YELLOW, -1)
        curses.init_pair(COLOR_ERROR, curses.COLOR_RED, -1)

    def _color(self, pair: int) -> int:
        if not curses.has_colors():
            return curses.A_NORMAL
        return curses.color_pair(pair)

    def _group_attr(self, group: WebGroup, selected: bool) -> int:
        attr = self._color(COLOR_BANNED if group.banned else COLOR_LIVE)
        if selected:
            attr |= curses.A_REVERSE
        return attr

    def _banned_row_attr(self, selected: bool) -> int:
        attr = self._color(COLOR_BANNED)
        if selected:
            attr |= curses.A_REVERSE
        return attr


def run_web_monitor(config: Config, log_file: Path | None = None, max_events: int = 1000) -> None:
    WebMonitorApp(config, log_file=log_file, max_events=max_events).run()


def sort_web_groups(groups: list[WebGroup], sort_mode: str) -> list[WebGroup]:
    if sort_mode == "count-desc":
        return sorted(groups, key=lambda item: (-item.count, -item.last_seen_at, item.ip))
    if sort_mode == "count-asc":
        return sorted(groups, key=lambda item: (item.count, -item.last_seen_at, item.ip))
    return sorted(groups, key=lambda item: (-item.last_seen_at, item.ip))


def current_display_time() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def build_web_groups(events: list[WebRequest], banned_ips: set[str]) -> list[WebGroup]:
    grouped: dict[str, list[WebRequest]] = {}
    for event in events:
        grouped.setdefault(event.ip, []).append(event)
    return [
        WebGroup(
            ip=ip,
            count=len(requests),
            requests=sorted(requests, key=lambda request: -request.observed_at),
            banned=ip in banned_ips,
        )
        for ip, requests in grouped.items()
    ]


def event_matches_filters(event: WebRequest, filters: WebFilterState) -> bool:
    if filters.ip and event.ip != filters.ip:
        return False
    if filters.start_at is not None and event.observed_at < filters.start_at:
        return False
    if filters.end_at is not None and event.observed_at > filters.end_at:
        return False
    return True


def apply_group_filters(groups: list[WebGroup], filters: WebFilterState) -> list[WebGroup]:
    result = groups
    if filters.country:
        result = [group for group in result if (group.country or "").upper() == filters.country]
    if filters.search:
        needle = filters.search.lower()
        result = [group for group in result if group_matches_search(group, needle)]
    return result


def group_matches_search(group: WebGroup, needle: str) -> bool:
    haystack = " ".join(
        [
            group.ip,
            group.last_seen,
            group.country or "",
            group.latest_status,
            group.top_paths,
        ]
    ).lower()
    return needle in haystack


def banned_row_matches_filters(row: BannedWebRow, filters: WebFilterState) -> bool:
    if filters.ip and row.ip != filters.ip:
        return False
    if filters.country and (row.country or "").upper() != filters.country:
        return False
    if filters.start_at is not None or filters.end_at is not None:
        created_at = parse_ban_created_at(row.created_at)
        last_seen_at = row.group.last_seen_at if row.group else None
        comparable = last_seen_at if last_seen_at is not None and last_seen_at > 0 else created_at
        if comparable is None:
            return False
        if filters.start_at is not None and comparable < filters.start_at:
            return False
        if filters.end_at is not None and comparable > filters.end_at:
            return False
    if filters.search:
        needle = filters.search.lower()
        haystack = " ".join(
            [
                row.ip,
                row.created_at,
                row.reason,
                row.country or "",
                row.last_seen,
                row.latest_status,
                row.top_paths,
            ]
        ).lower()
        return needle in haystack
    return True


def parse_date_range(value: str) -> tuple[float | None, float | None]:
    if ".." in value:
        start_text, end_text = value.split("..", 1)
    else:
        start_text, end_text = value, ""
    start = parse_filter_datetime(start_text)
    end = parse_filter_datetime(end_text)
    return start, end


def parse_filter_datetime(value: str) -> float | None:
    text = value.strip()
    if not text:
        return None
    parsed = parse_datetime(text)
    if parsed is None and len(text) == 10:
        parsed = parse_datetime(f"{text} 00:00:00")
    return parsed.timestamp() if parsed else None


def parse_ban_created_at(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return parse_filter_datetime(value)
