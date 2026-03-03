# MASS — Mac AI Security Sandbox

**Protect your Mac from AI agents accessing sensitive local data.**

AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Devin) run with your full user permissions. They can read your Chrome passwords, Keychain, SSH keys, crypto wallets, and chat history — by accident or by prompt injection.

MASS fixes this with one command. It uses macOS `sandbox-exec` for **kernel-level process isolation** with near-zero performance overhead.

```bash
mass launch claude    # Claude Code, sandboxed
mass launch cursor    # Cursor, sandboxed
mass launch <any>     # Any AI agent, sandboxed
```

## What Gets Blocked

| Category | Examples | Priority |
|----------|----------|----------|
| Hardware | Camera, microphone | P0 |
| Browsers | Chrome, Firefox, Safari, Edge, Brave, Arc, Opera, Vivaldi, Chromium, Tor | P0 |
| Crypto | OKX, Binance, Gate, Trezor, Coinbase, Exodus, Ledger, TradingView | P0 |
| Keychain | All keychain databases + `security` command | P0 |
| SSH/GPG | Private keys, agent sockets | P1 |
| Messaging | Telegram, Signal, Discord, WhatsApp, WeChat, Slack, iMessage | P1 |
| Dev credentials | AWS, Docker, Kubernetes, npm, PyPI | P2 |
| System | Cookies, Accounts databases | P2 |

**Everything else is allowed.** Your project files, Desktop, terminal tools, git, npm, python — all work normally.

## Quick Start

```bash
# Clone
git clone https://github.com/anthropics/mass.git ~/.mass
cd ~/.mass

# Install (auto-detects your apps, generates sandbox profile)
./mass install

# Launch your AI agent in the sandbox
./mass launch claude
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `mass install` | First-time setup: detect apps, generate sandbox, verify |
| `mass launch <cmd>` | Launch any command inside the sandbox |
| `mass launch --allow <path> <cmd>` | Launch with a temporary path exception |
| `mass check <path>` | Diagnose if a path is blocked and show which rule |
| `mass rules` | List all active deny rules |
| `mass test` | Run security verification tests |
| `mass scan` | Scan for newly installed apps not yet covered |
| `mass status` | Show protection status dashboard |

## If Something Gets Blocked

AI agents sometimes need access to paths that MASS blocks. Here's the workflow:

```bash
# 1. Check what's blocking you
mass check ~/.ssh/id_rsa
# → BLOCKED by: (deny file-read* (subpath "/Users/you/.ssh"))
# → To unblock: mass launch --allow "/Users/you/.ssh" claude

# 2. Launch with temporary exception (one session only)
mass launch --allow ~/.ssh claude

# 3. Or permanently: edit configs/sandbox.sb and remove the deny rule
```

The `--allow` flag removes specific deny rules for that session only. All other protections remain active.

## How It Works

```
┌─────────────────────────────────────────┐
│  mass launch claude                      │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  sandbox-exec -f sandbox.sb     │     │
│  │                                 │     │
│  │  (allow default)                │     │
│  │  (deny file-read* Chrome/...)   │     │ ← kernel-level
│  │  (deny file-read* Keychains/...)│     │   enforcement
│  │  (deny device-camera)           │     │
│  │  ...43 deny rules...            │     │
│  │                                 │     │
│  │  → claude (runs normally)       │     │
│  └─────────────────────────────────┘     │
│                                          │
│  Desktop/  ✅ allowed                    │
│  project/  ✅ allowed                    │
│  Chrome/   ❌ Operation not permitted    │
│  .ssh/     ❌ Operation not permitted    │
└─────────────────────────────────────────┘
```

- **Default allow**: Everything is permitted unless explicitly denied
- **Precise deny**: Only sensitive paths are blocked (not whole directories)
- **Kernel-level**: `sandbox-exec` runs in the macOS kernel — no userspace overhead
- **Process isolation**: The AI agent process itself cannot bypass the sandbox

## Project Structure

```
MASS/
├── mass                        # Main CLI (bash, single file)
├── configs/
│   ├── sandbox.sb.template     # Template with __HOME__ placeholders
│   └── sandbox.sb              # Generated profile (user-specific, gitignored)
├── docs/
│   └── methodology.md          # Security classification methodology
├── LICENSE                     # MIT
└── README.md                   # This file
```

## Customizing

### Add a new deny rule

Edit `configs/sandbox.sb.template`:

```scheme
;; My custom app
(deny file-read* (subpath "__HOME__/Library/Application Support/MyApp"))
```

Then re-run `mass install` to regenerate.

### Add to your shell profile

```bash
# ~/.zshrc or ~/.bashrc
alias claude-safe='/path/to/mass launch claude'
alias cursor-safe='/path/to/mass launch cursor'
```

## Requirements

- macOS 10.5+ (sandbox-exec is available on all modern macOS versions)
- Bash 3.2+ (ships with macOS)
- No dependencies, no sudo, no compilation

## FAQ

**Q: Will this break my AI agent?**
A: No. MASS uses `(allow default)` — everything is allowed except the specific sensitive paths listed. Your code, tools, and terminal work exactly as before.

**Q: What if I need to access a blocked path?**
A: Use `mass check <path>` to diagnose, then `mass launch --allow <path>` for a temporary exception. For permanent changes, edit the sandbox profile.

**Q: Is sandbox-exec deprecated?**
A: Apple has marked it as deprecated since macOS 10.15, but it remains functional (tested on macOS 15+). There is no replacement API for user-space process sandboxing. If Apple removes it, MASS will adapt.

**Q: Does this work with Docker / VS Code / other dev tools?**
A: Yes. Dev tools are not blocked. Only sensitive data paths (passwords, keys, wallets) are denied.

**Q: Can a smart AI agent bypass this?**
A: No. `sandbox-exec` is enforced at the kernel level. The sandboxed process has no way to escape — it would need a kernel exploit, which is far beyond any AI agent's capability.

## Threat Model

MASS protects against three attack vectors:

1. **AI hallucination**: Agent accidentally reads/writes sensitive files during task execution
2. **Prompt injection**: Malicious content in code/docs tricks the agent into exfiltrating data
3. **Context leakage**: Sensitive data read into agent context gets transmitted to cloud APIs

MASS does **not** protect against:
- Network-level attacks (use a firewall)
- Kernel exploits (use macOS updates)
- Physical access (use FileVault)

## Contributing

PRs welcome. Key areas:
- New browser/app profiles for the template
- Linux support (using seccomp/AppArmor)
- Windows support (using Windows Sandbox)
- Integration with specific AI agent frameworks

## License

MIT — use it however you want.

---

*Created by [小code](https://github.com/anthropics) & [Rob](https://robbery.blog) — born from the idea that AI agents deserve a home, but your passwords deserve a lock.*
