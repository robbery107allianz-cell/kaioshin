"""Markdown report generator.

Generates a full audit report in Markdown format,
saved to the reports/ directory.
"""

from datetime import datetime
from pathlib import Path

from kaioshin.scanner.extensions import ExtensionInfo
from kaioshin.scanner.secrets import SecretFinding
from kaioshin.scanner.wallets import WalletFinding
from kaioshin.scanner.network import ConnectionInfo
from kaioshin.scanner.ai_agents import AgentRating


def generate_report(
    extensions: list[ExtensionInfo],
    secrets: list[SecretFinding],
    wallets: list[WalletFinding],
    connections: list[ConnectionInfo],
    ai_ratings: list[AgentRating],
    output_dir: Path,
) -> Path:
    """Generate a full Markdown audit report."""
    now = datetime.now()
    filename = f"{now.strftime('%Y-%m-%d')}-audit.md"
    output_path = output_dir / filename

    lines = [
        f"# Kaioshin Security Audit — {now.strftime('%Y-%m-%d %H:%M')}",
        "",
        "---",
        "",
    ]

    # Summary
    ext_warnings = sum(1 for e in extensions if e.risk_level in ("critical", "high", "medium"))
    secret_exposed = sum(1 for s in secrets if s.status == "exposed")
    suspicious_conns = sum(1 for c in connections if c.suspicious)

    lines.extend([
        "## Summary",
        "",
        f"| Module | Count | Warnings |",
        f"|--------|-------|----------|",
        f"| Browser Extensions | {len(extensions)} | {ext_warnings} |",
        f"| Sensitive Files | {len(secrets)} | {secret_exposed} exposed |",
        f"| Wallet Exposure | {len(wallets)} | — |",
        f"| Network Connections | {len([c for c in connections if 'ESTABLISHED' in c.state.upper()])} active | {suspicious_conns} suspicious |",
        f"| AI Agents | {sum(1 for r in ai_ratings if r.installed)} installed | — |",
        "",
        "---",
        "",
    ])

    # Extensions
    lines.extend(["## 🧩 Browser Extensions", ""])
    if extensions:
        lines.extend([
            "| Risk | Name | Browser | Permissions | Version |",
            "|------|------|---------|-------------|---------|",
        ])
        for ext in extensions:
            perm_count = len(ext.permissions) + len(ext.host_permissions)
            lines.append(
                f"| **{ext.risk_level.upper()}** | {ext.name} | {ext.browser} | {perm_count} | {ext.version} |"
            )
        lines.append("")

        # Detail dangerous ones
        dangerous = [e for e in extensions if e.risk_level in ("critical", "high", "medium")]
        for ext in dangerous:
            lines.extend([
                f"### ⚠️ {ext.name} ({ext.browser})",
                "",
                f"- **ID**: `{ext.ext_id}`",
                f"- **Risk**: {ext.risk_level.upper()}",
                f"- **Path**: `{ext.path}`",
                "",
                "**Risk reasons:**",
            ])
            for reason in ext.risk_reasons:
                lines.append(f"- {reason}")
            lines.append("")
    else:
        lines.extend(["No browser extensions found.", ""])

    lines.extend(["---", ""])

    # Secrets
    lines.extend(["## 🔑 Sensitive Files", ""])
    if secrets:
        lines.extend([
            "| Severity | Category | Status | Path |",
            "|----------|----------|--------|------|",
        ])
        for f in secrets:
            lines.append(f"| {f.severity} | {f.category} | {f.status} | `{f.path}` |")
        lines.append("")

        exposed = [f for f in secrets if f.status == "exposed"]
        if exposed:
            lines.extend(["### Exposed items requiring action", ""])
            for f in exposed:
                lines.extend([
                    f"- **{f.category}** — `{f.path}`",
                    f"  - {f.detail}",
                ])
                if f.recommendation:
                    lines.append(f"  - 💡 {f.recommendation}")
            lines.append("")
    else:
        lines.extend(["No sensitive files found.", ""])

    lines.extend(["---", ""])

    # Wallets
    lines.extend(["## 💰 Wallet Exposure", ""])
    if wallets:
        for f in wallets:
            lines.extend([
                f"- **{f.wallet_name}** ({f.browser}) — {f.severity}",
                f"  - {f.detail}",
            ])
            if f.dapps:
                dapp_list = ", ".join(f.dapps[:10])
                lines.append(f"  - DApps: {dapp_list}")
        lines.append("")
    else:
        lines.extend(["No wallet exposure found.", ""])

    lines.extend(["---", ""])

    # Network
    lines.extend(["## 🌐 Network Connections", ""])
    suspicious = [c for c in connections if c.suspicious]
    if suspicious:
        lines.extend([
            "### ⚠️ Suspicious connections",
            "",
            "| Process | PID | Remote | Port | Reason |",
            "|---------|-----|--------|------|--------|",
        ])
        for c in suspicious:
            lines.append(f"| {c.process_name} | {c.pid} | {c.remote_addr} | {c.remote_port} | {c.reason} |")
        lines.append("")
    else:
        lines.extend(["No suspicious network connections detected.", ""])

    lines.extend(["---", ""])

    # AI Agents
    lines.extend(["## 🤖 AI Agent Security Ratings", ""])
    lines.extend([
        "| Agent | Installed | Rating | Key Strength | Key Risk |",
        "|-------|-----------|--------|-------------|----------|",
    ])
    for r in ai_ratings:
        stars = "★" * r.stars + "☆" * (5 - r.stars)
        strength = r.strengths[0] if r.strengths else "—"
        weakness = r.weaknesses[0] if r.weaknesses else "—"
        lines.append(
            f"| {r.name} | {'✅' if r.installed else '—'} | {stars} | {strength} | {weakness} |"
        )
    lines.append("")

    # Footer
    lines.extend([
        "---",
        "",
        f"*Generated by Kaioshin v2 — {now.strftime('%Y-%m-%d %H:%M:%S')}*",
        f"*Code & Rob · 1984*",
        "",
    ])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path
