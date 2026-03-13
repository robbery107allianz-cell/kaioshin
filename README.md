# Kaioshin 界王神 — Mac AI Security Sandbox

***The Supreme Kai of your Mac***

AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Devin) run with your full user permissions. They can read your Chrome passwords, Keychain, SSH keys, crypto wallets, and chat history — by accident or by prompt injection.

Kaioshin fixes this with one command. It uses macOS `sandbox-exec` for **kernel-level process isolation** with near-zero performance overhead.

```bash
kaioshin launch claude    # Claude Code, sandboxed
kaioshin launch gemini    # Gemini CLI, sandboxed
kaioshin launch cursor    # Cursor, sandboxed
kaioshin launch <any>     # Any AI agent, sandboxed
```

> *In Dragon Ball, the Kaiōshin (界王神) is the Supreme Kai — the divine guardian who watches over the universe. He doesn't interfere with daily life, but sets unbreakable rules that protect against catastrophic threats. That's exactly what this tool does for your Mac.*

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
git clone https://github.com/robbery107allianz-cell/kaioshin.git ~/.kaioshin
cd ~/.kaioshin

# Install (auto-detects your apps, generates sandbox profile)
./kaioshin install

# Launch your AI agent in the sandbox
./kaioshin launch claude
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `kaioshin install` | First-time setup: detect apps, generate sandbox, verify |
| `kaioshin launch <cmd>` | Launch any command inside the sandbox |
| `kaioshin launch --allow <path> <cmd>` | Launch with a temporary path exception |
| `kaioshin check <path>` | Diagnose if a path is blocked and show which rule |
| `kaioshin rules` | List all active deny rules |
| `kaioshin test` | Run security verification tests |
| `kaioshin scan` | Scan for newly installed apps not yet covered |
| `kaioshin status` | Show protection status dashboard |

## If Something Gets Blocked

AI agents sometimes need access to paths that Kaioshin blocks. Here's the workflow:

```bash
# 1. Diagnose what's blocking you
kaioshin check ~/.ssh/id_rsa
# → BLOCKED by: (deny file-read* (subpath "/Users/you/.ssh"))
# → To unblock: kaioshin launch --allow "/Users/you/.ssh" claude

# 2. Launch with temporary exception (one session only)
kaioshin launch --allow ~/.ssh claude

# 3. Or permanently: edit configs/sandbox.sb and remove the deny rule
```

The `--allow` flag removes specific deny rules for that session only. All other protections remain active.

## Verified Agents

Kaioshin uses process-level kernel sandboxing — it works with **any CLI agent**, present or future, without agent-specific configuration.

| Agent | Command | Status | Notes |
|-------|---------|--------|-------|
| **Claude Code** | `kaioshin launch claude` | Verified | Daily driver since 2026-03 |
| **Gemini CLI** | `kaioshin launch gemini` | Verified | Google Gemini 3, tested 2026-03-13 |
| **Cursor** | `kaioshin launch cursor` | Supported | Electron app, launch from terminal |
| **Copilot CLI** | `kaioshin launch gh copilot` | Supported | Untested, should work |
| **Any future agent** | `kaioshin launch <cmd>` | Supported | Kernel sandbox is agent-agnostic |

### Multi-agent test results (2026-03-13)

Gemini CLI was launched inside Kaioshin and instructed to read Chrome browser data:

```
Gemini → list_directory ~/Library/Application Support/Google/Chrome/
  → Error: EPERM: operation not permitted

Gemini's response: "内核层面的安全限制"
```

The agent attempted access, the kernel denied it. The agent itself was unaware it was sandboxed — Gemini's own status bar still displayed `no sandbox`. This confirms **kernel-level enforcement is transparent to the sandboxed process**.

### Security note: AI-layer refusal vs kernel-layer blocking

AI agents have two layers of defense:

| Layer | Mechanism | Bypassable? |
|-------|-----------|-------------|
| **AI model safety** | Agent refuses to read sensitive files based on its training | Yes — prompt injection, jailbreaks, or rephrased requests can bypass |
| **Kaioshin kernel sandbox** | macOS kernel denies file I/O at process level | No — requires a kernel exploit, far beyond any AI agent's capability |

When asked directly to "read Chrome passwords", Gemini's AI layer refused on ethical grounds. But when asked indirectly to "check Chrome disk usage", the AI layer allowed it — and **only Kaioshin's kernel sandbox stopped the actual access**. This demonstrates why both layers matter, and why the kernel layer is the one you can trust.

## How It Works

```
┌─────────────────────────────────────────┐
│  kaioshin launch claude                  │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  sandbox-exec -f sandbox.sb     │     │
│  │                                 │     │
│  │  (allow default)                │     │
│  │  (deny file-read* Chrome/...)   │     │ ← kernel-level
│  │  (deny file-read* Keychains/...)│     │   enforcement
│  │  (deny device-camera)           │     │
│  │  ...49 deny rules...            │     │
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
kaioshin/
├── kaioshin                    # Main CLI (bash, single file)
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

Then re-run `kaioshin install` to regenerate.

### Shell aliases

```bash
# ~/.zshrc or ~/.bashrc
alias ks='~/.kaioshin/kaioshin'
alias claude-safe='~/.kaioshin/kaioshin launch claude'
alias gemini-safe='~/.kaioshin/kaioshin launch gemini'
alias cursor-safe='~/.kaioshin/kaioshin launch cursor'
```

## Requirements

- macOS 10.5+ (sandbox-exec is available on all modern macOS versions)
- Bash 3.2+ (ships with macOS)
- No dependencies, no sudo, no compilation

## FAQ

**Q: Will this break my AI agent?**
A: No. Kaioshin uses `(allow default)` — everything is allowed except the specific sensitive paths listed. Your code, tools, and terminal work exactly as before.

**Q: What if I need to access a blocked path?**
A: Use `kaioshin check <path>` to diagnose, then `kaioshin launch --allow <path>` for a temporary exception.

**Q: Is sandbox-exec deprecated?**
A: Apple marked it as deprecated since macOS 10.15, but it remains functional (tested on macOS 15+). There is no replacement API for user-space process sandboxing.

**Q: Can a smart AI agent bypass this?**
A: No. `sandbox-exec` is enforced at the kernel level. The sandboxed process cannot escape — it would need a kernel exploit, which is far beyond any AI agent's capability.

## Known Limitations

**Keychain "not found" dialog may appear for sandboxed agents.**

Some agents (e.g., Gemini CLI) attempt to store OAuth credentials in the macOS Keychain. Since Kaioshin blocks Keychain access, macOS displays a "Keychain Not Found" dialog. **Click Cancel** — this is expected behavior and does not affect functionality. The agent falls back to file-based credential caching. Do NOT click "Reset To Defaults" as it may affect other applications' password storage.

**macOS `defaults read` bypasses file-level deny rules.**

The `defaults` command reads preferences through `cfprefsd` (an XPC service), not through direct file I/O. This means commands like `defaults read MobileMeAccounts` can still return iCloud account identities (email addresses, display names) even though the underlying plist file is blocked.

This is a macOS architecture constraint — `sandbox-exec` enforces file-level access control but cannot intercept XPC inter-process communication.

**What's exposed:** Apple ID email addresses, display names.
**What's NOT exposed:** Passwords, authentication tokens, Keychain data (all blocked).

**Recommendation:** Enable **two-factor authentication** (2FA) on all your Apple accounts. With 2FA active, a leaked email address alone has near-zero security impact. You can enable it at [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security → Two-Factor Authentication.

## Threat Model

Kaioshin protects against three attack vectors:

1. **AI hallucination**: Agent accidentally reads/writes sensitive files
2. **Prompt injection**: Malicious content tricks the agent into exfiltrating data
3. **Context leakage**: Sensitive data gets transmitted to cloud APIs

## Contributing

PRs welcome. Key areas:
- New browser/app profiles for the template
- Linux support (using seccomp/AppArmor)
- Windows support (using Windows Sandbox)
- Integration with specific AI agent frameworks

## License

MIT — use it however you want.

---

*Created by [小code](https://robbery.blog/search/label/AI) & [Rob](https://robbery.blog) — born in the 1984 Mac Homeland, inspired by Dragon Ball, built on the spirit of open source freedom.*

*The Supreme Kai doesn't fight. He sets the rules that protect the universe.*
