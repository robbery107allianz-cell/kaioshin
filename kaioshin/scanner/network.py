"""Network connection scanner.

Inspects active outbound connections for suspicious destinations,
unexpected processes with network access, raw IP connections, and
connection frequency anomalies.
"""

import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field


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
    severity: str = ""  # info, warning, critical


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
    1337: "Common hacker port",
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
    "brightdata",
    "luminati",
]

# Processes that should NOT have outbound network connections
# If these are connecting to the internet, something is wrong
UNEXPECTED_NETWORK_PROCESSES = {
    "Preview": "Image/PDF viewer should not need internet",
    "TextEdit": "Text editor should not need internet",
    "Calculator": "Calculator should not need internet",
    "Stickies": "Sticky notes should not need internet",
    "Chess": "Chess game should not need internet",
    "Grapher": "Graphing tool should not need internet",
    "Photo Booth": "Camera app should not need internet",
    "ScreenSaverEngine": "Screen saver should not need internet",
}

# Processes known to be safe with network access
EXPECTED_NETWORK_PROCESSES = {
    "Google", "Chrome", "firefox", "Safari", "Arc", "Brave", "Edge",
    "Opera", "Vivaldi", "Chromium",  # Browsers
    "node", "npm", "npx", "python3", "python", "ruby", "java",  # Runtimes
    "git", "ssh", "scp", "rsync", "curl", "wget",  # Dev tools
    "claude", "code", "cursor",  # AI/editors
    "Slack", "Discord", "Telegram", "WhatsApp", "WeChat", "zoom",  # Comms
    "Spotify", "Music", "iTunes",  # Media
    "Dropbox", "iCloud", "OneDrive", "Google Drive",  # Cloud sync
    "mDNSResponder", "configd", "apsd", "cloudd", "nsurlsessiond",  # System
    "rapportd", "WiFiAgent", "CommCenter", "identityservicesd",  # System
    "Mail", "Finder", "loginwindow", "UserEventAgent",  # macOS core
    "softwareupdated", "com.apple", "trustd", "syspolicyd",  # macOS services
    "Notes", "Reminders", "Calendar", "Contacts", "Photos",  # Apple apps
    "Messages", "FaceTime", "Maps", "News", "Stocks", "Weather",  # Apple apps
    "stable", "storedownloadd", "akd", "cloudfamilyd",  # macOS daemons
    "mediaremoted", "remindd", "callservicesd", "sharingd",  # macOS daemons
    "AMPDevicesAgent", "AMPLibraryAgent", "StoreSer",  # Apple services
    "accountsd", "passd", "kernelmanagerd", "notifyd",  # macOS system
    "symptomsd", "parsecd", "biomed", "healthd",  # macOS analytics
}

# Regex to detect raw IP addresses (not resolved to hostnames)
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Private/local IP ranges (not suspicious)
_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
                        "198.18.", "198.19.",  # macOS DNS proxy / content filter
                        "100.64.",  # Carrier-grade NAT (Tailscale, etc.)
                        "224.", "239.",  # Multicast
                        "255.",  # Broadcast
                        )


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

        connections.append(conn)

    return connections


def _check_suspicious(conn: ConnectionInfo) -> None:
    """Flag suspicious connections with severity levels."""

    # 1. Known malicious ports — CRITICAL
    if conn.remote_port in SUSPICIOUS_PORTS:
        conn.suspicious = True
        conn.severity = "critical"
        conn.reason = f"Malware-associated port {conn.remote_port}: {SUSPICIOUS_PORTS[conn.remote_port]}"
        return

    # 2. Known bad destinations — CRITICAL
    remote_lower = conn.remote_addr.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in remote_lower:
            conn.suspicious = True
            conn.severity = "critical"
            conn.reason = f"Known bandwidth-selling/proxy service: {pattern}"
            return

    # 3. Unexpected process with network access — WARNING
    for proc_name, reason in UNEXPECTED_NETWORK_PROCESSES.items():
        if proc_name.lower() in conn.process_name.lower():
            conn.suspicious = True
            conn.severity = "warning"
            conn.reason = f"Unexpected network access: {reason}"
            return

    # 4. Raw IP connection (no DNS) to non-private address — INFO
    if _IP_PATTERN.match(conn.remote_addr):
        if not conn.remote_addr.startswith(_PRIVATE_IP_PREFIXES):
            # Don't flag known safe processes
            is_known = any(
                safe.lower() in conn.process_name.lower()
                for safe in EXPECTED_NETWORK_PROCESSES
            )
            if not is_known:
                conn.suspicious = True
                conn.severity = "info"
                conn.reason = f"Direct IP connection (no DNS resolution) from unknown process"
                return


def _detect_frequency_anomalies(connections: list[ConnectionInfo]) -> list[ConnectionInfo]:
    """Detect processes with abnormally high connection counts."""
    anomalies = []

    # Count connections per process
    process_counts = Counter(c.process_name for c in connections if "ESTABLISHED" in c.state.upper())

    # Count unique remote destinations per process
    process_destinations: dict[str, set[str]] = {}
    for c in connections:
        if "ESTABLISHED" in c.state.upper():
            process_destinations.setdefault(c.process_name, set()).add(c.remote_addr)

    for proc_name, count in process_counts.items():
        unique_dests = len(process_destinations.get(proc_name, set()))

        # Flag: >30 active connections from a single process (excluding browsers)
        is_browser = any(b.lower() in proc_name.lower()
                        for b in ("chrome", "firefox", "safari", "arc", "brave", "edge"))
        if count > 30 and not is_browser:
            anomaly = ConnectionInfo(
                process_name=proc_name,
                pid=0,
                local_addr="",
                remote_addr=f"{unique_dests} unique destinations",
                remote_port=0,
                state=f"{count} connections",
                suspicious=True,
                severity="warning",
                reason=f"High connection volume: {count} active connections to {unique_dests} destinations",
            )
            anomalies.append(anomaly)

    return anomalies


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

        connections = _parse_lsof_output(result.stdout)

        # Run suspicion checks on each connection
        for conn in connections:
            _check_suspicious(conn)

        # Detect frequency anomalies
        anomalies = _detect_frequency_anomalies(connections)

        # Combine: suspicious connections + anomalies + all connections
        suspicious = [c for c in connections if c.suspicious]
        suspicious.extend(anomalies)

        # Sort: critical first, then warning, then info
        severity_order = {"critical": 0, "warning": 1, "info": 2, "": 3}
        suspicious.sort(key=lambda x: severity_order.get(x.severity, 3))

        return connections

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
