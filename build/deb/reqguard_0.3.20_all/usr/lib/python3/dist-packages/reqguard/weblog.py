from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

COMMON_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\S+)'
)

NODATE_RE = re.compile(
    r'^(?P<ip>\S+)(?: \S+ \S+)? '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

DEFAULT_LOG_CANDIDATES = [
    Path("/var/log/nginx/access.log"),
    Path("/var/log/apache2/access.log"),
]


@dataclass(frozen=True)
class WebRequest:
    ip: str
    method: str
    path: str
    protocol: str
    status: str
    user_agent: str = "-"
    referer: str = "-"
    host: str = "-"
    headers: str = "-"
    payload: str = "-"
    raw: str = ""
    observed_at: float = 0.0
    observed_time: str = "-"


@dataclass(frozen=True)
class WebGroup:
    ip: str
    count: int
    requests: list[WebRequest]
    banned: bool = False
    country: str | None = None

    @property
    def last_seen_at(self) -> float:
        return max((request.observed_at for request in self.requests), default=0.0)

    @property
    def last_seen(self) -> str:
        latest = max(self.requests, key=lambda request: request.observed_at, default=None)
        return latest.observed_time if latest else "-"

    @property
    def top_paths(self) -> str:
        counts: dict[str, int] = defaultdict(int)
        for request in self.requests:
            counts[request.path] += 1
        paths = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return ", ".join(f"{path}({count})" for path, count in paths[:3])

    @property
    def latest_status(self) -> str:
        return self.requests[0].status if self.requests else "-"

    @property
    def latest_user_agent(self) -> str:
        return self.requests[0].user_agent if self.requests else "-"


def default_log_file() -> Path:
    for path in DEFAULT_LOG_CANDIDATES:
        if path.exists():
            return path
    return DEFAULT_LOG_CANDIDATES[0]


def parse_log_line(line: str) -> WebRequest | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        return parse_json_line(line)
    return parse_access_line(line)


def parse_json_line(line: str) -> WebRequest | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    ip = first_value(data, "remote_addr", "client_ip", "ip", "remote_ip")
    method = first_value(data, "method", "request_method")
    path = first_value(data, "path", "uri", "request_uri")
    request = first_value(data, "request")
    if request and (not method or not path):
        parsed = split_request(request)
        method = method or parsed[0]
        path = path or parsed[1]
    if not ip or not path:
        return None
    headers = data.get("headers", "-")
    payload = first_value(data, "payload", "body", "request_body")
    observed_at, observed_time = observed_time_from_value(
        first_value(data, "time", "timestamp", "datetime", "time_local", "time_iso8601", "request_time")
    )
    return WebRequest(
        ip=str(ip),
        method=str(method or "-"),
        path=str(path),
        protocol=str(first_value(data, "protocol", "server_protocol") or "-"),
        status=str(first_value(data, "status", "status_code") or "-"),
        user_agent=str(first_value(data, "user_agent", "http_user_agent") or "-"),
        referer=str(first_value(data, "referer", "http_referer") or "-"),
        host=str(first_value(data, "host", "http_host") or "-"),
        headers=json.dumps(headers, sort_keys=True) if isinstance(headers, dict) else str(headers or "-"),
        payload=str(payload or "-"),
        raw=line,
        observed_at=observed_at,
        observed_time=observed_time,
    )


def parse_access_line(line: str) -> WebRequest | None:
    match = COMBINED_RE.match(line) or COMMON_RE.match(line) or NODATE_RE.match(line)
    if not match:
        return None
    method, path, protocol = split_request(match.group("request"))
    observed_at, observed_time = observed_time_from_value(match.groupdict().get("time"))
    return WebRequest(
        ip=match.group("ip"),
        method=method,
        path=path,
        protocol=protocol,
        status=match.group("status"),
        user_agent=match.groupdict().get("user_agent") or "-",
        referer=match.groupdict().get("referer") or "-",
        raw=line.strip(),
        observed_at=observed_at,
        observed_time=observed_time,
    )


def split_request(request: str) -> tuple[str, str, str]:
    parts = request.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], "-"
    if len(parts) == 1 and parts[0]:
        return "-", parts[0], "-"
    return "-", "-", "-"


def first_value(data: dict[str, object], *keys: str) -> object | None:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return None


def observed_time_from_value(value: object | None) -> tuple[float, str]:
    parsed = parse_datetime(value)
    if parsed is None:
        parsed = datetime.now().astimezone()
    return parsed.timestamp(), parsed.strftime("%Y-%m-%d %H:%M:%S")


def parse_datetime(value: object | None) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


class WebLogReader:
    def __init__(self, path: Path, max_events: int = 1000, start_at_end: bool = False) -> None:
        self.path = path
        self.max_events = max_events
        self.start_at_end = start_at_end
        self._fh = None
        self._position = 0
        self.events: deque[WebRequest] = deque(maxlen=max_events)

    def poll(self) -> list[WebRequest]:
        if self._fh is None:
            self._open()
        if self._fh is None:
            return []
        rows: list[WebRequest] = []
        while True:
            line = self._fh.readline()
            if not line:
                break
            parsed = parse_log_line(line)
            if parsed:
                self.events.append(parsed)
                rows.append(parsed)
        self._position = self._fh.tell()
        return rows

    def _open(self) -> None:
        if not self.path.exists():
            return
        self._fh = self.path.open("r", encoding="utf-8", errors="replace")
        if self.start_at_end:
            self._fh.seek(0, 2)
            self._position = self._fh.tell()
        else:
            self._read_recent()

    def _read_recent(self) -> None:
        if self._fh is None:
            return
        lines = deque(self._fh, maxlen=self.max_events)
        for line in lines:
            parsed = parse_log_line(line)
            if parsed:
                self.events.append(parsed)
        self._position = self._fh.tell()

    def groups(self, banned_ips: set[str]) -> list[WebGroup]:
        grouped: dict[str, list[WebRequest]] = defaultdict(list)
        for event in self.events:
            grouped[event.ip].append(event)
        groups = [
            WebGroup(
                ip=ip,
                count=len(requests),
                requests=sorted(requests, key=lambda request: -request.observed_at),
                banned=ip in banned_ips,
            )
            for ip, requests in grouped.items()
        ]
        return sorted(groups, key=lambda item: (-item.last_seen_at, item.ip))

    def wait_for_file(self, seconds: float) -> None:
        if self.path.exists():
            return
        time.sleep(seconds)
