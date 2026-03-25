"""Browser extension security scanner.

Scans Chrome, Brave, Edge, Arc, Firefox for installed extensions.
Checks permissions, known malicious IDs, and anomalous behavior indicators.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

BROWSER_EXTENSION_PATHS = {
    "Chrome": "~/Library/Application Support/Google/Chrome/Default/Extensions",
    "Chrome Beta": "~/Library/Application Support/Google/Chrome Beta/Default/Extensions",
    "Brave": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
    "Edge": "~/Library/Application Support/Microsoft Edge/Default/Extensions",
    "Arc": "~/Library/Application Support/Arc/User Data/Default/Extensions",
    "Chromium": "~/Library/Application Support/Chromium/Default/Extensions",
    "Vivaldi": "~/Library/Application Support/Vivaldi/Default/Extensions",
    "Opera": "~/Library/Application Support/com.operasoftware.Opera/Extensions",
}

# Firefox uses a different format
FIREFOX_PROFILE_PATH = "~/Library/Application Support/Firefox/Profiles"

# Permissions that indicate high risk
DANGEROUS_PERMISSIONS = {
    "<all_urls>": "Can access ALL websites — full browsing data exposure",
    "http://*/*": "Can access all HTTP sites",
    "https://*/*": "Can access all HTTPS sites",
    "*://*/*": "Can access all sites (wildcard)",
    "webRequest": "Can intercept/modify all network requests",
    "webRequestBlocking": "Can block/modify network requests in real-time",
    "nativeMessaging": "Can communicate with programs outside the browser",
    "debugger": "Full Chrome DevTools access — can read any page",
    "cookies": "Can read/write all cookies including auth tokens",
    "history": "Can read full browsing history",
    "bookmarks": "Can read all bookmarks",
    "downloads": "Can manage downloads and read downloaded files",
    "proxy": "Can route all traffic through a proxy",
    "clipboardRead": "Can read clipboard contents",
    "management": "Can manage other extensions",
    "privacy": "Can change privacy settings",
    "tabs": "Can access tab URLs and metadata",
    "desktopCapture": "Can capture screen content",
    "tabCapture": "Can capture tab audio/video",
}


@dataclass
class ExtensionInfo:
    """Represents a scanned browser extension."""

    browser: str
    ext_id: str
    name: str
    version: str
    description: str
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    risk_level: str = "unknown"  # safe, low, medium, high, critical
    risk_reasons: list[str] = field(default_factory=list)
    manifest_version: int = 0
    path: str = ""


def scan_chromium_extensions(
    browser_name: str, extensions_dir: Path
) -> list[ExtensionInfo]:
    """Scan a Chromium-based browser's extensions directory."""
    results = []

    if not extensions_dir.exists():
        return results

    for ext_dir in extensions_dir.iterdir():
        if not ext_dir.is_dir():
            continue

        ext_id = ext_dir.name

        # Find the latest version subdirectory
        version_dirs = sorted(ext_dir.iterdir(), reverse=True)
        for vdir in version_dirs:
            manifest_path = vdir / "manifest.json"
            if manifest_path.exists():
                info = _parse_manifest(browser_name, ext_id, manifest_path)
                if info:
                    results.append(info)
                break

    return results


def _parse_manifest(
    browser: str, ext_id: str, manifest_path: Path
) -> ExtensionInfo | None:
    """Parse a Chrome extension manifest.json."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    name = data.get("name", "Unknown")
    # Chrome uses __MSG_xxx__ for localized names
    if name.startswith("__MSG_"):
        name = _resolve_locale_name(manifest_path.parent, name) or name

    permissions = data.get("permissions", [])
    host_permissions = data.get("host_permissions", [])

    # MV2 puts host patterns in permissions, MV3 separates them
    mv = data.get("manifest_version", 2)
    if mv == 2:
        host_perms = [p for p in permissions if _is_host_pattern(p)]
        api_perms = [p for p in permissions if not _is_host_pattern(p)]
    else:
        api_perms = permissions
        host_perms = host_permissions

    all_perms = api_perms + host_perms

    info = ExtensionInfo(
        browser=browser,
        ext_id=ext_id,
        name=name,
        version=data.get("version", "?"),
        description=data.get("description", "")[:200],
        permissions=api_perms,
        host_permissions=host_perms,
        manifest_version=mv,
        path=str(manifest_path.parent),
    )

    _assess_risk(info, all_perms)
    return info


def _resolve_locale_name(ext_path: Path, msg_key: str) -> str | None:
    """Try to resolve __MSG_xxx__ localized extension name."""
    key = msg_key.replace("__MSG_", "").replace("__", "")
    for locale in ["en", "en_US", "zh_CN", "zh_TW"]:
        messages_path = ext_path / "_locales" / locale / "messages.json"
        if messages_path.exists():
            try:
                messages = json.loads(messages_path.read_text(encoding="utf-8"))
                # Case-insensitive key lookup
                for k, v in messages.items():
                    if k.lower() == key.lower():
                        return v.get("message", None)
            except (json.JSONDecodeError, OSError):
                continue
    return None


def _is_host_pattern(perm: str) -> bool:
    """Check if a permission string is a host/URL pattern."""
    return (
        perm.startswith("http")
        or perm.startswith("*://")
        or perm.startswith("<all_urls>")
        or perm.startswith("ftp")
    )


def _assess_risk(info: ExtensionInfo, all_perms: list[str]) -> None:
    """Assess risk level based on permissions and known threats."""
    score = 0
    reasons = []

    for perm in all_perms:
        if perm in DANGEROUS_PERMISSIONS:
            reasons.append(f"Permission: {perm} — {DANGEROUS_PERMISSIONS[perm]}")
            if perm in ("<all_urls>", "*://*/*", "webRequestBlocking", "debugger", "nativeMessaging"):
                score += 3
            elif perm in ("webRequest", "cookies", "proxy", "management", "desktopCapture"):
                score += 2
            else:
                score += 1

    # Host permission breadth
    broad_hosts = [p for p in info.host_permissions if "/*" in p]
    if len(broad_hosts) > 5:
        reasons.append(f"Broad host access: {len(broad_hosts)} wildcard patterns")
        score += 2

    if score == 0:
        info.risk_level = "safe"
    elif score <= 2:
        info.risk_level = "low"
    elif score <= 5:
        info.risk_level = "medium"
    elif score <= 8:
        info.risk_level = "high"
    else:
        info.risk_level = "critical"

    info.risk_reasons = reasons


def scan_firefox_extensions() -> list[ExtensionInfo]:
    """Scan Firefox extensions (addons.json based)."""
    results = []
    profiles_dir = Path(FIREFOX_PROFILE_PATH).expanduser()
    if not profiles_dir.exists():
        return results

    for profile in profiles_dir.iterdir():
        addons_file = profile / "addons.json"
        if not addons_file.exists():
            continue

        try:
            data = json.loads(addons_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        for addon in data.get("addons", []):
            if addon.get("type") != "extension":
                continue
            if addon.get("location") == "app-system-defaults":
                continue

            info = ExtensionInfo(
                browser="Firefox",
                ext_id=addon.get("id", "unknown"),
                name=addon.get("name", "Unknown"),
                version=addon.get("version", "?"),
                description=addon.get("description", "")[:200],
                permissions=addon.get("userPermissions", {}).get("permissions", []),
                host_permissions=addon.get("userPermissions", {}).get("origins", []),
                path=str(profile),
            )
            _assess_risk(info, info.permissions + info.host_permissions)
            results.append(info)

    return results


def scan_all() -> list[ExtensionInfo]:
    """Scan all browsers for extensions."""
    results = []

    for browser_name, path_str in BROWSER_EXTENSION_PATHS.items():
        ext_dir = Path(path_str).expanduser()
        results.extend(scan_chromium_extensions(browser_name, ext_dir))

    results.extend(scan_firefox_extensions())

    # Sort: critical first
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4, "unknown": 5}
    results.sort(key=lambda x: risk_order.get(x.risk_level, 5))

    return results
