"""Terminal output formatter with colored status indicators."""

from kaioshin.scanner.extensions import ExtensionInfo
from kaioshin.scanner.secrets import SecretFinding
from kaioshin.scanner.wallets import WalletFinding
from kaioshin.scanner.network import ConnectionInfo
from kaioshin.scanner.ai_agents import AgentRating

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

RISK_ICONS = {
    "critical": f"{RED}🔴",
    "high": f"{RED}⚠️ ",
    "medium": f"{YELLOW}⚠️ ",
    "low": f"{BLUE}ℹ️ ",
    "safe": f"{GREEN}✅",
    "unknown": f"{DIM}❓",
}

SEVERITY_ICONS = {
    "P0": f"{RED}🔴",
    "P1": f"{YELLOW}⚠️ ",
    "P2": f"{BLUE}ℹ️ ",
}

STATUS_ICONS = {
    "exposed": f"{RED}EXPOSED{RESET}",
    "encrypted": f"{GREEN}Encrypted{RESET}",
    "present": f"{YELLOW}Present{RESET}",
    "system_protected": f"{GREEN}System-managed{RESET}",
    "low_risk": f"{GREEN}Low risk{RESET}",
    "missing": f"{DIM}Not found{RESET}",
    "unreadable": f"{DIM}Unreadable{RESET}",
}


def print_header():
    """Print scan header."""
    print(f"""
{BOLD}🔍 Kaioshin v2 — Mac Security Audit{RESET}
{'━' * 50}
""")


def print_extensions(extensions: list[ExtensionInfo]):
    """Print extension scan results."""
    if not extensions:
        print(f"{BOLD}🧩 Browser Extensions{RESET}          No extensions found\n")
        return

    warnings = sum(1 for e in extensions if e.risk_level in ("critical", "high", "medium"))
    total = len(extensions)

    color = RED if warnings > 0 else GREEN
    print(f"{BOLD}🧩 Browser Extensions{RESET}          {total} scanned, {color}{warnings} WARNING{RESET}")

    for ext in extensions:
        icon = RISK_ICONS.get(ext.risk_level, "")
        print(f"  {icon} {ext.name}{RESET} ({ext.browser})")
        print(f"     {DIM}Risk: {ext.risk_level.upper()} | Permissions: {len(ext.permissions) + len(ext.host_permissions)} | MV{ext.manifest_version}{RESET}")
        if ext.risk_reasons:
            for reason in ext.risk_reasons[:3]:
                print(f"     {DIM}→ {reason}{RESET}")

    print()


def print_secrets(findings: list[SecretFinding]):
    """Print secrets scan results."""
    if not findings:
        print(f"{BOLD}🔑 Sensitive Files{RESET}             No sensitive files found\n")
        return

    exposed = sum(1 for f in findings if f.status == "exposed")
    total = len(findings)

    color = RED if exposed > 0 else GREEN
    print(f"{BOLD}🔑 Sensitive Files{RESET}             {total} items, {color}{exposed} exposed{RESET}")

    for f in findings:
        icon = SEVERITY_ICONS.get(f.severity, "")
        status = STATUS_ICONS.get(f.status, f.status)
        print(f"  {icon} {f.category}{RESET}  [{status}]")
        print(f"     {DIM}{f.path}{RESET}")
        print(f"     {DIM}{f.detail}{RESET}")
        if f.recommendation:
            print(f"     {YELLOW}→ {f.recommendation}{RESET}")

    print()


def print_wallets(findings: list[WalletFinding]):
    """Print wallet scan results."""
    if not findings:
        print(f"{BOLD}💰 Wallet Exposure{RESET}             No wallets found\n")
        return

    total = len(findings)
    print(f"{BOLD}💰 Wallet Exposure{RESET}             {total} findings")

    for f in findings:
        icon = SEVERITY_ICONS.get(f.severity, "")
        print(f"  {icon} {f.wallet_name}{RESET} ({f.browser})")
        print(f"     {DIM}{f.detail}{RESET}")
        if f.dapps:
            dapp_list = ", ".join(f.dapps[:5])
            remaining = f.dapp_count - 5
            suffix = f" +{remaining} more" if remaining > 0 else ""
            print(f"     {DIM}DApps: {dapp_list}{suffix}{RESET}")

    print()


def print_network(connections: list[ConnectionInfo]):
    """Print network scan results."""
    suspicious = [c for c in connections if c.suspicious]
    critical = [c for c in suspicious if c.severity == "critical"]
    warnings = [c for c in suspicious if c.severity == "warning"]
    infos = [c for c in suspicious if c.severity == "info"]
    established = [c for c in connections if "ESTABLISHED" in c.state.upper()]

    color = RED if critical else YELLOW if warnings else GREEN
    print(f"{BOLD}🌐 Network Connections{RESET}         {len(established)} active, {color}{len(suspicious)} flagged{RESET}")

    if critical:
        for conn in critical:
            print(f"  {RED}🔴 {conn.process_name}{RESET} (PID {conn.pid})")
            print(f"     {DIM}→ {conn.remote_addr}:{conn.remote_port}{RESET}")
            print(f"     {RED}{conn.reason}{RESET}")

    if warnings:
        for conn in warnings:
            print(f"  {YELLOW}⚠️  {conn.process_name}{RESET} (PID {conn.pid})")
            if conn.remote_port:
                print(f"     {DIM}→ {conn.remote_addr}:{conn.remote_port}{RESET}")
            else:
                print(f"     {DIM}→ {conn.remote_addr} ({conn.state}){RESET}")
            print(f"     {YELLOW}{conn.reason}{RESET}")

    if infos:
        for conn in infos:
            print(f"  {BLUE}ℹ️  {conn.process_name}{RESET} (PID {conn.pid})")
            print(f"     {DIM}→ {conn.remote_addr}:{conn.remote_port}{RESET}")
            print(f"     {DIM}{conn.reason}{RESET}")

    if not suspicious:
        print(f"  {GREEN}✅ No suspicious connections detected{RESET}")

    print()


def print_ai_agents(ratings: list[AgentRating]):
    """Print AI agent security ratings."""
    installed = [r for r in ratings if r.installed]
    print(f"{BOLD}🤖 AI Agent Security{RESET}           {len(installed)} installed")

    for r in ratings:
        if not r.installed:
            continue
        stars = "★" * r.stars + "☆" * (5 - r.stars)
        color = GREEN if r.stars >= 4 else YELLOW if r.stars >= 3 else RED
        print(f"  {color}{stars}{RESET}  {r.name}")
        print(f"     {DIM}{r.detail}{RESET}")
        if r.strengths:
            print(f"     {GREEN}+ {r.strengths[0]}{RESET}")
        if r.weaknesses:
            print(f"     {RED}- {r.weaknesses[0]}{RESET}")

    # Show not-installed as dim
    not_installed = [r for r in ratings if not r.installed]
    if not_installed:
        names = ", ".join(r.name for r in not_installed)
        print(f"  {DIM}Not installed: {names}{RESET}")

    print()


def print_footer(report_path: str | None = None):
    """Print scan footer."""
    print(f"{'━' * 50}")
    if report_path:
        print(f"📄 Full report: {report_path}")
    print()
