from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address


TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass(frozen=True)
class Connection:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: str
    pid: int | None = None
    process: str | None = None
    service: str | None = None
    hostname: str | None = None
    country: str | None = None
    banned: bool = False
    observed_at: float = 0.0
    observed_time: str = "-"

    @property
    def is_inbound(self) -> bool:
        try:
            remote = ip_address(self.remote_ip)
        except ValueError:
            return False
        return not (
            remote.is_loopback
            or remote.is_unspecified
            or remote.is_multicast
            or self.state == "LISTEN"
        )


@dataclass(frozen=True)
class BanEntry:
    ip: str
    reason: str
    created_at: str
    ports: tuple[int, ...] = ()

    @classmethod
    def create(cls, ip: str, reason: str = "", ports: tuple[int, ...] = ()) -> "BanEntry":
        return cls(
            ip=str(ip_address(ip)),
            reason=reason,
            created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            ports=ports,
        )
