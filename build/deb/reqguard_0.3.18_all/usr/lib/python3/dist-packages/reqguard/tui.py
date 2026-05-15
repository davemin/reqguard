from __future__ import annotations

import curses
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime

from .banlist import BanList
from .config import Config
from .enrich import CountryLookup, reverse_dns
from .firewall import ban_ip, unban_ip
from .models import BanEntry, Connection
from .procnet import read_connections
from .text import safe_terminal_text


TITLE = "Reqguard network monitor"
HELP = "v/Tab view | / search | i IP | d date range | c country | x clear | s sort | b ban | u unban | q quit"
DETAIL_COLUMNS = "    Seen                Remote endpoint           -> Local endpoint          State       Process"
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
class MonitorFilterState:
    search: str = ""
    ip: str = ""
    country: str = ""
    start_at: float | None = None
    end_at: float | None = None
    date_label: str = ""


@dataclass(frozen=True)
class IpGroup:
    ip: str
    count: int
    connections: list[Connection]
    country: str | None = None
    hostname: str | None = None
    banned: bool = False

    @property
    def last_seen_at(self) -> float:
        return max((conn.observed_at for conn in self.connections), default=0.0)

    @property
    def last_seen(self) -> str:
        latest = max(self.connections, key=lambda conn: conn.observed_at, default=None)
        return latest.observed_time if latest else "-"

    @property
    def services(self) -> str:
        ports = sorted({conn.local_port for conn in self.connections})
        return ",".join(str(port) for port in ports[:6]) + ("..." if len(ports) > 6 else "")

    @property
    def processes(self) -> str:
        names = sorted({conn.process for conn in self.connections if conn.process})
        return ",".join(names[:3]) + ("..." if len(names) > 3 else "")


@dataclass(frozen=True)
class BannedIpRow:
    entry: BanEntry
    group: IpGroup | None = None
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
    def hostname(self) -> str | None:
        return self.group.hostname if self.group else None

    @property
    def services(self) -> str:
        return self.group.services if self.group else "-"

    @property
    def processes(self) -> str:
        return self.group.processes if self.group else "-"


class MonitorApp:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.banlist = BanList(config.bans_file)
        self.country_lookup = CountryLookup(
            config.geoip_db,
            config.country_provider,
            config.country_cache_file,
            config.ip_lookup_url,
        )
        self.sort_mode = config.sort_mode
        self.view_mode = VIEW_REQUESTS
        self.filters = MonitorFilterState()
        self.selected = 0
        self.expanded: set[str] = set()
        self.connection_seen: dict[tuple[str, str, int, str, int, str], tuple[float, str]] = {}
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
        groups: list[IpGroup] = []
        banned_rows: list[BannedIpRow] = []
        visible_rows: list[IpGroup | BannedIpRow] = []
        while True:
            now = time.monotonic()
            if now - last_refresh >= self.config.refresh_seconds:
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
                self.filters = MonitorFilterState()
                self.message = "filters cleared"
                groups = self._groups()
                banned_rows = self._banned_rows(groups)
                visible_rows = self._visible_rows(groups, banned_rows)
                self.selected = min(self.selected, max(len(visible_rows) - 1, 0))
            elif key in {ord("s"), ord("S")}:
                self._cycle_sort()
                last_refresh = 0.0
            elif key in {ord("r"), ord("R")}:
                last_refresh = 0.0
            elif key in {ord("b"), ord("B")} and visible_rows and self.view_mode == VIEW_REQUESTS:
                self._ban(visible_rows[self.selected])
                last_refresh = 0.0
            elif key in {ord("u"), ord("U")} and visible_rows and self.view_mode == VIEW_BANS:
                self._unban_ip(visible_rows[self.selected].ip)
                last_refresh = 0.0

    def _groups(self) -> list[IpGroup]:
        bans = self.banlist.load()
        by_ip: dict[str, list[Connection]] = defaultdict(list)
        active_keys: set[tuple[str, str, int, str, int, str]] = set()
        for conn in read_connections():
            key = (
                conn.protocol,
                conn.local_ip,
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
                conn.inode,
            )
            active_keys.add(key)
            if key not in self.connection_seen:
                self.connection_seen[key] = (
                    (conn.observed_at, conn.observed_time)
                    if conn.observed_at > 0
                    else current_observed_time()
                )
            observed_at, observed_time = self.connection_seen[key]
            hostname = reverse_dns(conn.remote_ip) if self.config.reverse_dns else None
            enriched = replace(
                conn,
                hostname=hostname,
                country=self.country_lookup.country(conn.remote_ip),
                banned=conn.remote_ip in bans,
                observed_at=observed_at,
                observed_time=observed_time,
            )
            if connection_matches_filters(enriched, self.filters):
                by_ip[enriched.remote_ip].append(enriched)
        for key in set(self.connection_seen) - active_keys:
            self.connection_seen.pop(key, None)

        groups = [
            IpGroup(
                ip=ip,
                count=len(connections),
                connections=sorted(
                    connections,
                    key=lambda item: (-item.observed_at, item.local_port, item.remote_port, item.state),
                ),
                country=connections[0].country,
                hostname=connections[0].hostname,
                banned=ip in bans,
            )
            for ip, connections in by_ip.items()
        ]
        groups = apply_monitor_group_filters(groups, self.filters)
        return sort_ip_groups(groups, self.sort_mode)

    def _banned_rows(self, groups: list[IpGroup]) -> list[BannedIpRow]:
        group_by_ip = {group.ip: group for group in groups}
        rows = [
            BannedIpRow(
                entry=entry,
                group=group_by_ip.get(entry.ip),
                cached_country=self.country_lookup.country(entry.ip),
            )
            for entry in self.banlist.load().values()
        ]
        rows = [row for row in rows if banned_ip_row_matches_filters(row, self.filters)]
        return sorted(rows, key=lambda row: (-(row.group.last_seen_at if row.group else 0), row.ip))

    def _visible_rows(self, groups: list[IpGroup], banned_rows: list[BannedIpRow]) -> list[IpGroup | BannedIpRow]:
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
        value = self._prompt(stdscr, "Search IP/date/country/host/ports (empty clears): ")
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

    def _ban(self, group: IpGroup) -> None:
        try:
            ban_ip(group.ip, backend=self.config.firewall_backend)
            try:
                self.banlist.add(group.ip, reason=f"manual from monitor count={group.count}")
            except Exception:
                unban_ip(group.ip, backend=self.config.firewall_backend)
                raise
            self.message = f"banned {group.ip}"
        except Exception as exc:
            self.message = f"ban failed: {exc}"

    def _unban_ip(self, ip: str) -> None:
        try:
            unban_ip(ip, backend=self.config.firewall_backend)
            self.banlist.remove(ip)
            self.message = f"unbanned {ip}"
        except Exception as exc:
            self.message = f"unban failed: {exc}"

    def _draw(
        self,
        stdscr: curses.window,
        groups: list[IpGroup],
        banned_rows: list[BannedIpRow],
        visible_rows: list[IpGroup | BannedIpRow],
        last_refresh_time: str,
    ) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 8 or width < 72:
            stdscr.addnstr(0, 0, "Terminal too small for reqguard. Resize to at least 72x8.", width - 1)
            stdscr.refresh()
            return

        total_connections = sum(item.count for item in visible_rows)
        selected_row = visible_rows[self.selected] if visible_rows else None

        self._draw_header(stdscr, width, len(banned_rows), len(visible_rows), total_connections, last_refresh_time)
        if self.message:
            attr = self._color(COLOR_ERROR if "failed" in self.message else COLOR_STATUS)
            stdscr.addnstr(2, 0, f"Last action: {safe_terminal_text(self.message)}", width - 1, attr)
        else:
            stdscr.addnstr(2, 0, "Last action: none", width - 1, self._color(COLOR_DETAIL))
        stdscr.addnstr(3, 0, self._filter_summary().ljust(width - 1), width - 1, self._color(COLOR_DETAIL))

        columns = (
            "Status  Last seen           IP remoto          Conn  Country   Hostname/Server                 Porte locali"
            if self.view_mode == VIEW_REQUESTS
            else "Created at                 IP remoto          Conn  Country   Hostname/Reason                 Porte locali"
        )
        stdscr.addnstr(4, 0, columns, width - 1, curses.A_BOLD)
        stdscr.hline(5, 0, curses.ACS_HLINE, width - 1)

        list_bottom = max(6, height - 5)
        row = 6
        for idx, item in enumerate(visible_rows):
            if row >= list_bottom:
                break
            if isinstance(item, BannedIpRow):
                attr = self._banned_row_attr(idx == self.selected)
                marker = "-" if item.ip in self.expanded else "+"
                country = safe_terminal_text(item.country or "--")
                host_or_reason = safe_terminal_text(item.hostname or item.reason)
                line = (
                    f"{marker} {safe_terminal_text(item.created_at):<24.24} {item.ip:<18} {item.count:<5} {country:<8} "
                    f"{host_or_reason:<31.31} {safe_terminal_text(item.services):<16.16}"
                )
            else:
                attr = self._group_attr(item, idx == self.selected)
                marker = "-" if item.ip in self.expanded else "+"
                country = safe_terminal_text(item.country or "--")
                host = safe_terminal_text(item.hostname or "-")
                line = (
                    f"LIVE   {marker} {item.last_seen:<19} {item.ip:<18} {item.count:<5} {country:<8} "
                    f"{host:<31.31} {safe_terminal_text(item.services):<16.16}"
                )
            stdscr.addnstr(row, 0, line, width - 1, attr)
            row += 1
            detail_group = item.group if isinstance(item, BannedIpRow) else item
            if item.ip in self.expanded and detail_group:
                row = self._draw_group_details(stdscr, row, width, list_bottom, detail_group)
        self._draw_selected_summary(stdscr, height, width, selected_row)
        stdscr.refresh()

    def _draw_group_details(
        self,
        stdscr: curses.window,
        row: int,
        width: int,
        height: int,
        group: IpGroup,
    ) -> int:
        if row < height:
            stdscr.addnstr(row, 0, DETAIL_COLUMNS, width - 1, curses.A_DIM)
            row += 1
        for conn in group.connections:
            if row >= height:
                break
            local = f"{conn.local_ip}:{conn.local_port}"
            remote = f"{conn.remote_ip}:{conn.remote_port}"
            proc = safe_terminal_text(f"{conn.process or '-'}" + (f"[{conn.pid}]" if conn.pid else ""))
            detail = (
                f"    {conn.observed_time:<19} {safe_terminal_text(remote):<24.24} -> "
                f"{safe_terminal_text(local):<22.22} {safe_terminal_text(conn.state):<11.11} {proc:<18.18}"
            )
            stdscr.addnstr(row, 0, detail, width - 1, self._color(COLOR_DETAIL))
            row += 1
        return row

    def _draw_header(
        self,
        stdscr: curses.window,
        width: int,
        bans_count: int,
        ip_count: int,
        total_connections: int,
        last_refresh_time: str,
    ) -> None:
        title = f" {TITLE} "
        stdscr.addnstr(0, 0, title.ljust(width - 1), width - 1, self._color(COLOR_HEADER) | curses.A_BOLD)
        stats = (
            f"View: {self.view_mode}   IPs shown: {ip_count}   Active TCP connections shown: {total_connections}   "
            f"Persisted bans shown: {bans_count}/{len(self.banlist.load())}   Sort: {self.sort_mode}   "
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
        item: IpGroup | BannedIpRow | None,
    ) -> None:
        top = height - 4
        stdscr.hline(top, 0, curses.ACS_HLINE, width - 1)
        if not item:
            stdscr.addnstr(top + 1, 0, f"No rows in {self.view_mode} view. Waiting for traffic or adjust filters.", width - 1)
        elif isinstance(item, BannedIpRow):
            expanded = "expanded" if item.ip in self.expanded else "collapsed"
            summary = (
                f"Selected ban: {item.ip}   Created: {item.created_at}   Active connections in filters: {item.count}   "
                f"Country: {item.country or '--'}   View: {expanded}"
            )
            stdscr.addnstr(top + 1, 0, summary, width - 1, self._color(COLOR_BANNED))
            detail = f"Reason: {safe_terminal_text(item.reason)}   Hostname: {safe_terminal_text(item.hostname or '-')}"
            stdscr.addnstr(top + 2, 0, detail, width - 1, self._color(COLOR_DETAIL))
        else:
            expanded = "expanded" if item.ip in self.expanded else "collapsed"
            summary = (
                f"Selected: {item.ip} [LIVE]   Connections: {item.count}   "
                f"Last seen: {item.last_seen}   Country: {item.country or '--'}   View: {expanded}"
            )
            stdscr.addnstr(top + 1, 0, summary, width - 1, self._group_attr(item, False))
            host = safe_terminal_text(item.hostname or "-")
            ports = safe_terminal_text(item.services or "-")
            procs = safe_terminal_text(item.processes or "-")
            detail = f"Hostname: {host}   Local ports: {ports}   Processes: {procs}"
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

    def _group_attr(self, group: IpGroup, selected: bool) -> int:
        attr = self._color(COLOR_BANNED if group.banned else COLOR_LIVE)
        if selected:
            attr |= curses.A_REVERSE
        return attr

    def _banned_row_attr(self, selected: bool) -> int:
        attr = self._color(COLOR_BANNED)
        if selected:
            attr |= curses.A_REVERSE
        return attr


def run_monitor(config: Config) -> None:
    MonitorApp(config).run()


def current_observed_time() -> tuple[float, str]:
    now = datetime.now().astimezone()
    return now.timestamp(), now.strftime("%Y-%m-%d %H:%M:%S")


def current_display_time() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def sort_ip_groups(groups: list[IpGroup], sort_mode: str) -> list[IpGroup]:
    if sort_mode == "count-desc":
        return sorted(groups, key=lambda item: (-item.count, -item.last_seen_at, item.ip))
    if sort_mode == "count-asc":
        return sorted(groups, key=lambda item: (item.count, -item.last_seen_at, item.ip))
    return sorted(groups, key=lambda item: (-item.last_seen_at, item.ip))


def connection_matches_filters(conn: Connection, filters: MonitorFilterState) -> bool:
    if filters.ip and conn.remote_ip != filters.ip:
        return False
    if filters.start_at is not None and conn.observed_at < filters.start_at:
        return False
    if filters.end_at is not None and conn.observed_at > filters.end_at:
        return False
    return True


def apply_monitor_group_filters(groups: list[IpGroup], filters: MonitorFilterState) -> list[IpGroup]:
    result = groups
    if filters.country:
        result = [group for group in result if (group.country or "").upper() == filters.country]
    if filters.search:
        needle = filters.search.lower()
        result = [group for group in result if monitor_group_matches_search(group, needle)]
    return result


def monitor_group_matches_search(group: IpGroup, needle: str) -> bool:
    haystack = " ".join(
        [
            group.ip,
            group.last_seen,
            group.country or "",
            group.hostname or "",
            group.services,
            group.processes,
        ]
    ).lower()
    return needle in haystack


def banned_ip_row_matches_filters(row: BannedIpRow, filters: MonitorFilterState) -> bool:
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
                row.hostname or "",
                row.services,
                row.processes,
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
    if len(text) == 10:
        text = f"{text} 00:00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def parse_ban_created_at(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return parse_filter_datetime(value)
