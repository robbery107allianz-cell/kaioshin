"""Markdown report generator.

Generates a full audit report in Markdown format with human-readable
fix guides that don't require CLI AI tools to follow.
"""

from datetime import datetime
from pathlib import Path

from kaioshin.scanner.extensions import ExtensionInfo
from kaioshin.scanner.secrets import SecretFinding
from kaioshin.scanner.wallets import WalletFinding
from kaioshin.scanner.network import ConnectionInfo
from kaioshin.scanner.ai_agents import AgentRating


# ── Human-readable fix guides ────────────────────────────────────────────────

FIX_GUIDES = {
    "SSH Keys": {
        "exposed": """
**这是什么**: SSH 私钥是你登录远程服务器的"钥匙"。未加密意味着任何能读到这个文件的程序都能用它登录你的服务器。

**为什么危险**: 恶意浏览器扩展、木马程序如果获得文件读取权限，可以直接复制你的私钥，远程登录你的服务器——不需要密码。

**修复步骤**（3 分钟）:
1. 打开终端（启动台 → 其他 → 终端）
2. 输入: `ssh-keygen -p -f {path}`
3. 输入新密码（之后每次 SSH 连接时需要输入，或用 macOS Keychain 记住）
4. 重新运行 `python3 kai scan secrets` 确认状态变为 Encrypted
""",
    },
    "AWS Credentials": {
        "exposed": """
**这是什么**: AWS 凭证文件包含你的云服务访问密钥。明文存储意味着任何程序都能读取并使用它操作你的 AWS 账户。

**为什么危险**: 攻击者拿到 AWS access key 后可以启动大量服务器挖矿，一夜之间产生数千美元账单——这是真实发生过的事。

**修复步骤**（10 分钟）:
1. **短期**: 登录 AWS Console → IAM → 你的用户 → 安全凭证 → 轮换访问密钥
2. **长期**: 迁移到 AWS SSO / IAM Identity Center（不再需要本地保存密钥）
3. 或安装 `aws-vault`（加密存储凭证）: `brew install aws-vault`
4. 重新运行 `python3 kai scan secrets` 确认
""",
    },
    "Env Files": {
        "exposed": """
**这是什么**: .env 文件通常包含 API 密钥、数据库密码等敏感配置。

**为什么危险**: 如果 .env 被意外提交到 GitHub（很常见的事故），你的密钥会被全球扫描器在几秒内发现并滥用。

**修复步骤**（2 分钟）:
1. 确认项目的 `.gitignore` 包含 `.env`
2. 运行: `git status` 确认 .env 没有被追踪
3. 如果已经提交过: 立即轮换所有 .env 中的密钥（git 历史里的密钥已经泄露）
4. 考虑使用 secret manager（如 1Password CLI、Doppler）替代 .env 文件
""",
    },
}

EXTENSION_FIX_GUIDE = """
**如何检查这个扩展是否安全**:
1. 打开 Chrome → 地址栏输入 `chrome://extensions/`
2. 找到 "{name}" → 点击"详情"
3. 查看"权限"列表，对照上方的风险原因
4. 如果你不认识或不再使用这个扩展 → 直接点"移除"
5. 在 Chrome Web Store 搜索该扩展名，查看用户评价和最近更新日期

**判断标准**:
- 最近 6 个月没更新 + 高权限 = 高风险（可能被收购后注入恶意代码）
- 用户少于 1000 + 高权限 = 高风险
- 开源（GitHub 可查看代码）= 较低风险
"""

WALLET_FIX_GUIDE = """
**钱包安全建议**:
1. **定期检查 DApp 授权**: 访问 https://revoke.cash 连接钱包，撤销不再使用的 DApp 授权
2. **大额资产**: 转移到硬件钱包（Ledger/Trezor），浏览器扩展钱包只保留日常使用的少量资金
3. **扩展更新**: 确保钱包扩展始终是最新版本（Chrome 自动更新，但可以手动检查）
4. **独立浏览器**: 考虑用独立的浏览器 Profile 专门做 DeFi 操作，与日常浏览隔离
"""

NETWORK_FIX_GUIDES = {
    "critical": """
**立即行动**:
1. 打开活动监视器（启动台 → 其他 → 活动监视器）
2. 搜索进程名，确认是什么程序
3. 如果不认识 → 选中进程 → 点击 ✕ 强制退出
4. 检查是否是浏览器扩展导致: Chrome → 更多工具 → 任务管理器，查看哪个扩展在消耗网络
5. 如果是已知恶意服务（Grass、Honeygain 等）→ 立即卸载对应扩展
""",
    "warning": """
**排查步骤**:
1. 打开活动监视器 → 网络标签
2. 找到对应进程，观察其上传/下载数据量
3. 如果一个不应该联网的程序在大量传输数据 → 可能是恶意软件伪装
4. 在终端运行 `lsof -i -n -P | grep {pid}` 查看该进程的所有网络连接
""",
}


# ── Report generation ────────────────────────────────────────────────────────

def generate_report(
    extensions: list[ExtensionInfo],
    secrets: list[SecretFinding],
    wallets: list[WalletFinding],
    connections: list[ConnectionInfo],
    ai_ratings: list[AgentRating],
    output_dir: Path,
) -> Path:
    """Generate a full Markdown audit report with fix guides."""
    now = datetime.now()
    filename = f"{now.strftime('%Y-%m-%d')}-audit.md"
    output_path = output_dir / filename

    lines = [
        f"# Kaioshin Security Audit — {now.strftime('%Y-%m-%d %H:%M')}",
        "",
        "> 本报告由 Kaioshin v2 自动生成。每个问题附带修复指南，无需 AI 工具即可操作。",
        "",
        "---",
        "",
    ]

    # ── Summary ──
    ext_warnings = sum(1 for e in extensions if e.risk_level in ("critical", "high", "medium"))
    secret_exposed = sum(1 for s in secrets if s.status == "exposed")
    suspicious_conns = sum(1 for c in connections if c.suspicious)

    lines.extend([
        "## Summary",
        "",
        "| Module | Count | Issues |",
        "|--------|-------|--------|",
        f"| 🧩 Browser Extensions | {len(extensions)} | {ext_warnings} warnings |",
        f"| 🔑 Sensitive Files | {len(secrets)} | {secret_exposed} exposed |",
        f"| 💰 Wallet Exposure | {len(wallets)} | {len(wallets)} findings |",
        f"| 🌐 Network | {len([c for c in connections if 'ESTABLISHED' in c.state.upper()])} active | {suspicious_conns} flagged |",
        f"| 🤖 AI Agents | {sum(1 for r in ai_ratings if r.installed)} installed | — |",
        "",
        "---",
        "",
    ])

    # ── Extensions ──
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
            lines.append(EXTENSION_FIX_GUIDE.format(name=ext.name))
            lines.append("")
    else:
        lines.extend(["No browser extensions found.", ""])

    lines.extend(["---", ""])

    # ── Secrets ──
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
            lines.extend(["### 🚨 Exposed — Requires Action", ""])
            for f in exposed:
                lines.extend([
                    f"#### {f.category} — `{f.path}`",
                    "",
                    f"**Status**: {f.detail}",
                    "",
                ])
                # Add fix guide if available
                guide = FIX_GUIDES.get(f.category, {}).get("exposed", "")
                if guide:
                    lines.append(guide.format(path=f.path).strip())
                elif f.recommendation:
                    lines.append(f"💡 **Recommendation**: {f.recommendation}")
                lines.append("")
    else:
        lines.extend(["No sensitive files found.", ""])

    lines.extend(["---", ""])

    # ── Wallets ──
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
        lines.append(WALLET_FIX_GUIDE.strip())
        lines.append("")
    else:
        lines.extend(["No wallet exposure found.", ""])

    lines.extend(["---", ""])

    # ── Network ──
    lines.extend(["## 🌐 Network Connections", ""])
    suspicious = [c for c in connections if c.suspicious]
    if suspicious:
        critical = [c for c in suspicious if c.severity == "critical"]
        warnings = [c for c in suspicious if c.severity == "warning"]
        infos = [c for c in suspicious if c.severity == "info"]

        if critical:
            lines.extend([
                "### 🔴 Critical — Immediate Action Required",
                "",
                "| Process | PID | Remote | Port | Reason |",
                "|---------|-----|--------|------|--------|",
            ])
            for c in critical:
                lines.append(f"| {c.process_name} | {c.pid} | {c.remote_addr} | {c.remote_port} | {c.reason} |")
            lines.append("")
            lines.append(NETWORK_FIX_GUIDES["critical"].strip())
            lines.append("")

        if warnings:
            lines.extend([
                "### ⚠️ Warning — Investigate",
                "",
                "| Process | PID | Remote | Detail | Reason |",
                "|---------|-----|--------|--------|--------|",
            ])
            for c in warnings:
                detail = f"{c.remote_addr}:{c.remote_port}" if c.remote_port else c.state
                lines.append(f"| {c.process_name} | {c.pid} | {c.remote_addr} | {detail} | {c.reason} |")
            lines.append("")
            lines.append(NETWORK_FIX_GUIDES["warning"].format(pid="<PID>").strip())
            lines.append("")

        if infos:
            lines.extend([
                "### ℹ️ Info — Low Risk",
                "",
                "| Process | PID | Remote | Port | Reason |",
                "|---------|-----|--------|------|--------|",
            ])
            for c in infos:
                lines.append(f"| {c.process_name} | {c.pid} | {c.remote_addr} | {c.remote_port} | {c.reason} |")
            lines.append("")
    else:
        lines.extend(["✅ No suspicious network connections detected.", ""])

    lines.extend(["---", ""])

    # ── AI Agents ──
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

    # ── Footer ──
    lines.extend([
        "---",
        "",
        "## How to Use This Report",
        "",
        "1. **Start with the Summary** — focus on items marked as warnings or exposed",
        "2. **Follow the fix guides** — each issue has step-by-step instructions you can follow in Terminal or System Settings",
        "3. **Re-scan after fixing** — run `python3 kai scan` again to verify your fixes worked",
        "4. **Schedule regular scans** — run monthly to catch new threats (new extensions, leaked credentials, etc.)",
        "",
        "> No AI tools required to follow these guides. Every step uses macOS built-in tools or your web browser.",
        "",
        "---",
        "",
        f"*Generated by Kaioshin v2 — {now.strftime('%Y-%m-%d %H:%M:%S')}*",
        f"*Code & Rob · 1984*",
        "",
    ])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path
