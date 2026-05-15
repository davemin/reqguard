from __future__ import annotations

import os
import socket
from pathlib import Path

from .models import Connection, TCP_STATES


PROC_ROOT = Path("/proc")
PROC_NET_TCP = Path("/proc/net/tcp")
PROC_NET_TCP6 = Path("/proc/net/tcp6")


def parse_ipv4(hex_value: str) -> str:
    raw = bytes.fromhex(hex_value)
    return socket.inet_ntop(socket.AF_INET, raw[::-1])


def parse_ipv6(hex_value: str) -> str:
    raw = bytes.fromhex(hex_value)
    words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def parse_address(value: str, ipv6: bool) -> tuple[str, int]:
    host_hex, port_hex = value.split(":")
    host = parse_ipv6(host_hex) if ipv6 else parse_ipv4(host_hex)
    return host, int(port_hex, 16)


def read_tcp_file(path: Path, protocol: str) -> list[Connection]:
    if not path.exists():
        return []
    ipv6 = protocol == "tcp6"
    connections: list[Connection] = []
    with path.open("r", encoding="utf-8") as fh:
        next(fh, None)
        for line in fh:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_ip, local_port = parse_address(parts[1], ipv6)
            remote_ip, remote_port = parse_address(parts[2], ipv6)
            state = TCP_STATES.get(parts[3], parts[3])
            connections.append(
                Connection(
                    protocol=protocol,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    inode=parts[9],
                )
            )
    return connections


def inode_process_map(proc_root: Path = PROC_ROOT) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    if not proc_root.exists():
        return result
    for pid_name in os.listdir(proc_root):
        if not pid_name.isdigit():
            continue
        fd_dir = proc_root / pid_name / "fd"
        comm_path = proc_root / pid_name / "comm"
        try:
            process_name = comm_path.read_text(encoding="utf-8").strip()
            for fd_name in os.listdir(fd_dir):
                try:
                    target = os.readlink(fd_dir / fd_name)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    result[inode] = (int(pid_name), process_name)
        except OSError:
            continue
    return result


def service_name(port: int, protocol: str = "tcp") -> str | None:
    try:
        return socket.getservbyport(port, "tcp" if protocol.startswith("tcp") else protocol)
    except OSError:
        return None


def read_connections() -> list[Connection]:
    proc_map = inode_process_map()
    connections = read_tcp_file(PROC_NET_TCP, "tcp") + read_tcp_file(PROC_NET_TCP6, "tcp6")
    enriched: list[Connection] = []
    for conn in connections:
        pid_process = proc_map.get(conn.inode)
        pid = pid_process[0] if pid_process else None
        process = pid_process[1] if pid_process else None
        service = service_name(conn.local_port, conn.protocol)
        enriched.append(
            Connection(
                protocol=conn.protocol,
                local_ip=conn.local_ip,
                local_port=conn.local_port,
                remote_ip=conn.remote_ip,
                remote_port=conn.remote_port,
                state=conn.state,
                inode=conn.inode,
                pid=pid,
                process=process,
                service=service,
            )
        )
    return [conn for conn in enriched if conn.is_inbound]
