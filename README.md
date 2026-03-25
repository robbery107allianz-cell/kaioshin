# Kaioshin 界王神 — Mac Security Auditor

*The Supreme Kai doesn't fight. He watches, detects, and reports.*

---

## What is this?

Kaioshin scans your Mac for real security threats — malicious browser extensions, exposed credentials, crypto wallet vulnerabilities, suspicious network connections, and AI tool security posture.

**Not a sandbox. Not a firewall. A security auditor that tells you what's actually exposed.**

### Why?

A Chrome extension called Grass uploaded 5.7GB of data in 3 hours through a user's browser, selling their bandwidth as a residential proxy. The user had no idea.

That's not a hypothetical. It happened. And it's the kind of threat that antivirus software doesn't catch, because the extension had user-granted permissions.

Kaioshin catches it.

---

## Quick Start

```bash
# Clone
git clone https://github.com/robbery107allianz-cell/kaioshin.git
cd kaioshin

# Run (zero dependencies — uses Python 3.11+ standard library)
python3 kai scan
```

That's it. No install, no pip, no venv needed.

> PyYAML is optional — only needed if you want to extend the knowledge base.

---

## What It Scans

### 🧩 Browser Extensions
- Scans Chrome, Brave, Edge, Arc, Firefox, Vivaldi, Opera, Chromium
- Analyzes every extension's permissions against a danger matrix
- Flags `<all_urls>`, `webRequestBlocking`, `nativeMessaging`, `debugger`, etc.
- Risk rating: Safe → Low → Medium → High → Critical

### 🔑 Sensitive Files
- SSH keys (encrypted vs unencrypted)
- AWS/GCP/Docker/npm/Kubernetes credentials
- macOS Keychain exposure
- `.env` files with API keys
- File permission audit (group/other readable?)

### 💰 Crypto Wallet Exposure
- Detects 13+ wallet extensions (MetaMask, Phantom, Coinbase, etc.)
- Scans IndexedDB for DApp authorization traces
- Checks for desktop wallets (Exodus, Electrum, Ledger, Trezor)

### 🌐 Network Connections
- Lists all active outbound connections via `lsof`
- Flags connections to known bandwidth-selling services
- Detects suspicious ports (Metasploit, RAT, IRC C2, etc.)

### 🤖 AI Agent Security Ratings
- Rates installed AI coding tools on a ★★★★★ scale
- Evaluates: file access control, sandboxing, permission model
- Currently rates: Claude Code, Cursor, Copilot, Gemini CLI, Windsurf, Devin

---

## Commands

```bash
kai scan                 # Full audit — all modules, generates report
kai scan extensions      # Browser extensions only
kai scan secrets         # Sensitive files only
kai scan wallets         # Crypto wallet exposure only
kai scan network         # Network connections only
kai scan ai              # AI tool security ratings only
kai report               # Show latest report path
kai version              # Show version
```

---

## Output

### Terminal
Colored output with risk icons, sorted by severity. Designed to be readable at a glance.

### Markdown Report
Full scan automatically generates `reports/YYYY-MM-DD-audit.md` — a detailed audit report you can share, archive, or track over time.

---

## Architecture

```
kaioshin/
├── kai                          # CLI entry point
├── kaioshin/                    # Python package
│   ├── cli.py                   # Command parser
│   ├── scanner/                 # Scan modules
│   │   ├── extensions.py        # Browser extension analysis
│   │   ├── secrets.py           # Sensitive file detection
│   │   ├── wallets.py           # Crypto wallet exposure
│   │   ├── network.py           # Network connection audit
│   │   └── ai_agents.py        # AI tool security ratings
│   ├── reporter/                # Output formatters
│   │   ├── terminal.py          # Colored terminal output
│   │   └── markdown.py          # Markdown report generator
│   └── knowledge/               # Threat intelligence
│       ├── malicious_extensions.yaml
│       └── risk_matrix.yaml
├── reports/                     # Generated audit reports
├── pyproject.toml
└── LICENSE                      # MIT
```

---

## Design Principles

1. **Read-only** — Kaioshin never modifies, deletes, or writes to any scanned location
2. **No sensitive data in output** — reports show file paths and metadata, never contents
3. **Zero required dependencies** — runs on Python 3.11+ standard library alone
4. **No root required** — all scans use standard user permissions
5. **Offline** — no network calls, no telemetry, no cloud

---

## History

- **v1** (2026-03-03): Mac AI Security Sandbox — `sandbox-exec` based process isolation
- **v2** (2026-03-25): Pivoted to security auditor after experiments proved real threats are malicious extensions, not AI agents

---

## License

MIT — Code & Rob · 1984
