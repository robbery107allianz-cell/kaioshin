"""Kaioshin CLI — Mac Security Auditor.

Usage:
    kai scan                 Full security audit (all modules)
    kai scan extensions      Browser extension scan only
    kai scan network         Network connection scan only
    kai scan wallets         Crypto wallet exposure scan only
    kai scan secrets         Sensitive file scan only
    kai scan ai              AI agent security ratings only
    kai report               Show path to latest report
    kai version              Show version
"""

import sys
from pathlib import Path

from kaioshin import __version__
from kaioshin.scanner import extensions, secrets, wallets, network, ai_agents
from kaioshin.reporter import terminal, markdown


def _get_reports_dir() -> Path:
    """Get the reports output directory."""
    # Find project root (where pyproject.toml lives)
    here = Path(__file__).resolve().parent.parent
    return here / "reports"


def cmd_scan(modules: list[str] | None = None):
    """Run security scan."""
    run_all = not modules or "all" in modules

    terminal.print_header()

    ext_results = []
    secret_results = []
    wallet_results = []
    network_results = []
    ai_results = []

    if run_all or "extensions" in modules:
        ext_results = extensions.scan_all()
        terminal.print_extensions(ext_results)

    if run_all or "secrets" in modules:
        secret_results = secrets.scan_all()
        terminal.print_secrets(secret_results)

    if run_all or "wallets" in modules:
        wallet_results = wallets.scan_all()
        terminal.print_wallets(wallet_results)

    if run_all or "network" in modules:
        network_results = network.scan_all()
        terminal.print_network(network_results)

    if run_all or "ai" in modules:
        ai_results = ai_agents.scan_all()
        terminal.print_ai_agents(ai_results)

    # Generate markdown report for full scans
    report_path = None
    if run_all:
        report_path = markdown.generate_report(
            extensions=ext_results,
            secrets=secret_results,
            wallets=wallet_results,
            connections=network_results,
            ai_ratings=ai_results,
            output_dir=_get_reports_dir(),
        )

    terminal.print_footer(str(report_path) if report_path else None)


def cmd_report():
    """Show latest report."""
    reports_dir = _get_reports_dir()
    if not reports_dir.exists():
        print("No reports found. Run 'kai scan' first.")
        return

    reports = sorted(reports_dir.glob("*-audit.md"), reverse=True)
    if reports:
        print(f"Latest report: {reports[0]}")
    else:
        print("No reports found. Run 'kai scan' first.")


def main():
    """CLI entry point."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return

    if args[0] in ("-v", "--version", "version"):
        print(f"Kaioshin v{__version__}")
        return

    if args[0] == "scan":
        modules = args[1:] if len(args) > 1 else None
        cmd_scan(modules)
        return

    if args[0] == "report":
        cmd_report()
        return

    print(f"Unknown command: {args[0]}")
    print("Run 'kai --help' for usage.")
    sys.exit(1)


if __name__ == "__main__":
    main()
