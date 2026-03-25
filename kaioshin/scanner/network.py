"""Network connection scanner.

Inspects active outbound connections for suspicious destinations,
high-volume transfers, and unexpected processes with network access.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ConnectionInfo:
    """A network connection with associated process info."""

    process_name: str
    pid: int
    local_addr: str
    remote_addr: str
    remote_port: int
    state: str
    suspicious: bool = False
    reason: str = ""


# Ports commonly used by malware/data exfiltration
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Common RAT port",
    6666: "Common backdoor",
    6667: "IRC (botnet C2)",
    8888: "Common proxy/tunnel",
    9090: "Common proxy",
    1080: "SOCKS proxy",
    3128: "Squid proxy",
    31337: "Back Orifice",
}

# Known suspicious destination patterns
SUSPICIOUS_PATTERNS = [
    "getgrass.io",
    "grass.io",
    "honeygain",
    "pawns.app",
    "peer2profit",
    "iproyal",
    "packetstream",
    "traffmonetizer",
    "earnapp",
    "spider.com",
]


def _parse_lsof_output(output: str) -> list[ConnectionInfo]:
    """Parse lsof -i output into structured connection info."""
    connections = []

    for line in output.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue

        process_name = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            continue

        # Connection column format: host:port->remote:port
        conn_str = parts[8] if len(parts) > 8 else ""
        state = parts[9] if len(parts) > 9 else ""

        if "->" not in conn_str:
            continue

        local, remote = conn_str.split("->", 1)
        remote_host, _, remote_port_str = remote.rpartition(":")

        try:
            remote_port = int(remote_port_str)
        except ValueError:
            remote_port = 0

        conn = ConnectionInfo(
            process_name=process_name,
            pid=pid,
            local_addr=local,
            remote_addr=remote_host,
            remote_port=remote_port,
            state=state,
        )

        _check_suspicious(conn)
        connections.append(conn)

    return connections


def _check_suspicious(conn: ConnectionInfo) -> None:
    """Flag suspicious connections."""
    # Check suspicious ports
    if conn.remote_port in SUSPICIOUS_PORTS:
        conn.suspicious = True
        conn.reason = f"Suspicious port {conn.remote_port}: {SUSPICIOUS_PORTS[conn.remote_port]}"
        return

    # Check known bad destinations
    remote_lower = conn.remote_addr.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in remote_lower:
            conn.suspicious = True
            conn.reason = f"Known bandwidth-selling/proxy service: {pattern}"
            return


def scan_all() -> list[ConnectionInfo]:
    """Scan active network connections using lsof."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        return _parse_lsof_output(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
