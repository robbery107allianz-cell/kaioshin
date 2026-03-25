"""Crypto wallet exposure scanner.

Checks for wallet browser extensions, local wallet data,
and DApp authorization exposure in IndexedDB/LevelDB.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

# Known wallet extensions and their Chrome Web Store IDs
KNOWN_WALLET_EXTENSIONS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "aiifbnbfobpmeekipheeijimdpnlpgpp": "Station Wallet (Terra)",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
    "jblndlipeogpafnldhgmapagcccfchpi": "Kaikas (Klaytn)",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "lgmpcpglpngdoalbgeoldeajfclnhbfk": "SafePal",
    "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin Wallet",
    "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus",
}

BROWSER_PROFILES = {
    "Chrome": "~/Library/Application Support/Google/Chrome/Default",
    "Brave": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default",
    "Edge": "~/Library/Application Support/Microsoft Edge/Default",
    "Arc": "~/Library/Application Support/Arc/User Data/Default",
}


@dataclass
class WalletFinding:
    """A discovered wallet or DApp exposure."""

    wallet_name: str
    browser: str
    finding_type: str  # extension_found, indexeddb_exposure, local_storage
    severity: str  # P0, P1, P2
    detail: str
    path: str = ""
    dapp_count: int = 0
    dapps: list[str] = field(default_factory=list)


def _scan_wallet_extensions(browser: str, profile_dir: Path) -> list[WalletFinding]:
    """Check if wallet extensions are installed in a browser."""
    findings = []
    ext_dir = profile_dir / "Extensions"

    if not ext_dir.exists():
        return findings

    for ext_id, wallet_name in KNOWN_WALLET_EXTENSIONS.items():
        wallet_dir = ext_dir / ext_id
        if wallet_dir.exists():
            findings.append(
                WalletFinding(
                    wallet_name=wallet_name,
                    browser=browser,
                    finding_type="extension_found",
                    severity="P1",
                    detail=f"{wallet_name} extension installed in {browser}",
                    path=str(wallet_dir),
                )
            )

    return findings


def _scan_indexeddb_dapps(browser: str, profile_dir: Path) -> list[WalletFinding]:
    """Scan IndexedDB for DApp authorization traces."""
    findings = []
    indexeddb_dir = profile_dir / "IndexedDB"

    if not indexeddb_dir.exists():
        return findings

    # Known DApp/DeFi domains
    defi_keywords = [
        "uniswap", "opensea", "aave", "compound", "sushiswap",
        "pancakeswap", "curve", "1inch", "dydx", "raydium",
        "jupiter", "orca", "lido", "eigenlayer", "blur",
        "metamask", "phantom", "coinbase", "binance",
    ]

    dapp_dirs = []
    try:
        for item in indexeddb_dir.iterdir():
            name_lower = item.name.lower()
            for keyword in defi_keywords:
                if keyword in name_lower:
                    dapp_dirs.append(item.name)
                    break
    except PermissionError:
        return findings

    if dapp_dirs:
        findings.append(
            WalletFinding(
                wallet_name="DApp Traces",
                browser=browser,
                finding_type="indexeddb_exposure",
                severity="P1",
                detail=f"Found {len(dapp_dirs)} DApp/DeFi traces in IndexedDB",
                path=str(indexeddb_dir),
                dapp_count=len(dapp_dirs),
                dapps=dapp_dirs[:20],  # cap at 20
            )
        )

    return findings


def _scan_local_wallets() -> list[WalletFinding]:
    """Scan for standalone desktop wallet applications."""
    findings = []
    home = Path.home()

    desktop_wallets = {
        "Exodus": home / "Library" / "Application Support" / "Exodus",
        "Electrum": home / ".electrum" / "wallets",
        "Bitcoin Core": home / "Library" / "Application Support" / "Bitcoin",
        "Ledger Live": home / "Library" / "Application Support" / "@ledgerhq",
        "Trezor Suite": home / "Library" / "Application Support" / "@trezor" / "suite-desktop",
    }

    for wallet_name, wallet_path in desktop_wallets.items():
        if wallet_path.exists():
            try:
                size = sum(f.stat().st_size for f in wallet_path.rglob("*") if f.is_file())
                size_mb = size / (1024 * 1024)
            except (PermissionError, OSError):
                size_mb = 0

            findings.append(
                WalletFinding(
                    wallet_name=wallet_name,
                    browser="Desktop",
                    finding_type="local_wallet",
                    severity="P0",
                    detail=f"{wallet_name} data found ({size_mb:.1f} MB)",
                    path=str(wallet_path),
                )
            )

    return findings


def scan_all() -> list[WalletFinding]:
    """Scan all browsers and local storage for wallet exposure."""
    findings = []

    for browser, path_str in BROWSER_PROFILES.items():
        profile_dir = Path(path_str).expanduser()
        if not profile_dir.exists():
            continue
        findings.extend(_scan_wallet_extensions(browser, profile_dir))
        findings.extend(_scan_indexeddb_dapps(browser, profile_dir))

    findings.extend(_scan_local_wallets())

    severity_order = {"P0": 0, "P1": 1, "P2": 2}
    findings.sort(key=lambda x: severity_order.get(x.severity, 9))

    return findings
