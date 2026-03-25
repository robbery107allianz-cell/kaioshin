"""Local sensitive file scanner.

Detects exposed SSH keys, API credentials, tokens, and other secrets
that may be accessible to malicious software.
"""

from dataclasses import dataclass, field
from pathlib import Path

# Sensitive file patterns to check
SENSITIVE_PATHS = {
    "SSH Keys": {
        "paths": [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/id_ecdsa",
            "~/.ssh/id_dsa",
        ],
        "severity": "P0",
        "description": "SSH private keys — server access",
    },
    "AWS Credentials": {
        "paths": ["~/.aws/credentials", "~/.aws/config"],
        "severity": "P0",
        "description": "AWS access keys — cloud infrastructure",
    },
    "GCP Credentials": {
        "paths": [
            "~/.config/gcloud/application_default_credentials.json",
            "~/.config/gcloud/credentials.db",
        ],
        "severity": "P0",
        "description": "Google Cloud credentials",
    },
    "GPG Private Keys": {
        "paths": ["~/.gnupg/private-keys-v1.d/"],
        "severity": "P1",
        "description": "GPG signing/encryption keys",
    },
    "Docker Config": {
        "paths": ["~/.docker/config.json"],
        "severity": "P1",
        "description": "Docker registry auth tokens",
    },
    "npm Token": {
        "paths": ["~/.npmrc"],
        "severity": "P1",
        "description": "npm registry auth token",
    },
    "Kubernetes Config": {
        "paths": ["~/.kube/config"],
        "severity": "P1",
        "description": "Kubernetes cluster credentials",
    },
    "macOS Keychain": {
        "paths": [
            "~/Library/Keychains/login.keychain-db",
            "~/Library/Keychains/keychain-2.db",
        ],
        "severity": "P2",
        "description": "macOS Keychain — encrypted, requires Touch ID/password to read plaintext",
    },
    "Apple Identity": {
        "paths": [
            "~/Library/Accounts/Accounts4.sqlite",
            "~/Library/Preferences/MobileMeAccounts.plist",
        ],
        "severity": "P1",
        "description": "Apple ID and iCloud account data",
    },
    "Env Files": {
        "paths": [],  # dynamically scanned
        "severity": "P1",
        "description": ".env files with API keys and secrets",
    },
}


@dataclass
class SecretFinding:
    """A discovered sensitive file or credential."""

    category: str
    path: str
    severity: str  # P0, P1, P2
    status: str  # exposed, encrypted, missing
    detail: str
    recommendation: str = ""


def _check_ssh_key_encryption(key_path: Path) -> bool:
    """Check if an SSH private key file is encrypted."""
    try:
        content = key_path.read_text(encoding="utf-8", errors="ignore")
        # Encrypted keys contain ENCRYPTED in the header
        if "ENCRYPTED" in content:
            return True
        # OpenSSH new format: check for bcrypt/aes
        if "openssh-key-v1" in content:
            # Read as bytes to check encryption marker
            raw = key_path.read_bytes()
            # Unencrypted keys have "none" as cipher
            return b"none" not in raw[:200]
        return False
    except OSError:
        return False


def _check_aws_credentials(path: Path, size: int, perm_info: str) -> tuple[str, str, str]:
    """Check if AWS credentials file contains plaintext access keys."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        has_key = "aws_access_key_id" in content.lower()
        has_secret = "aws_secret_access_key" in content.lower()
        if has_key and has_secret:
            return (
                "exposed",
                f"Plaintext AWS access key + secret ({size} bytes). {perm_info}",
                "Migrate to AWS SSO / IAM Identity Center, or use aws-vault",
            )
        if has_key:
            return (
                "exposed",
                f"Contains access key ID but no secret ({size} bytes). {perm_info}",
                "Review if this file is still needed",
            )
        return (
            "present",
            f"AWS config file, no plaintext keys detected ({size} bytes). {perm_info}",
            "",
        )
    except OSError:
        return ("present", f"File exists ({size} bytes). {perm_info}", "")


def _check_file_permissions(path: Path) -> str:
    """Check if file has overly permissive permissions."""
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:  # readable by group or others
            return f"WARNING: permissions {oct(mode)} — accessible by other users"
        return f"OK: permissions {oct(mode)}"
    except OSError:
        return "Unable to check permissions"


def _scan_env_files(home: Path) -> list[SecretFinding]:
    """Scan common project directories for .env files."""
    findings = []
    search_dirs = [
        home / "Desktop",
        home / "Documents",
        home / "Projects",
        home / "1984",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        # Only scan 2 levels deep to avoid going into node_modules etc.
        for env_file in search_dir.glob("*/.env"):
            findings.append(_check_env_file(env_file))
        for env_file in search_dir.glob("*/.env.*"):
            if env_file.suffix not in (".example", ".template", ".sample"):
                findings.append(_check_env_file(env_file))

    return findings


def _check_env_file(env_path: Path) -> SecretFinding:
    """Analyze a .env file for secrets."""
    try:
        content = env_path.read_text(encoding="utf-8", errors="ignore")
        lines = [l for l in content.splitlines() if "=" in l and not l.strip().startswith("#")]
        secret_keys = [
            l.split("=")[0].strip()
            for l in lines
            if any(
                kw in l.split("=")[0].upper()
                for kw in ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"]
            )
        ]
        if secret_keys:
            return SecretFinding(
                category="Env Files",
                path=str(env_path),
                severity="P1",
                status="exposed",
                detail=f"Contains {len(secret_keys)} secret-like keys: {', '.join(secret_keys[:5])}",
                recommendation="Use a secret manager or ensure .gitignore covers this file",
            )
        return SecretFinding(
            category="Env Files",
            path=str(env_path),
            severity="P2",
            status="low_risk",
            detail=f"Contains {len(lines)} variables, no obvious secrets",
        )
    except OSError:
        return SecretFinding(
            category="Env Files",
            path=str(env_path),
            severity="P2",
            status="unreadable",
            detail="Cannot read file",
        )


def scan_all() -> list[SecretFinding]:
    """Scan all known sensitive file locations."""
    findings = []
    home = Path.home()

    for category, config in SENSITIVE_PATHS.items():
        if category == "Env Files":
            findings.extend(_scan_env_files(home))
            continue

        for path_str in config["paths"]:
            path = Path(path_str).expanduser()

            if not path.exists():
                continue

            if path.is_dir():
                # Check if directory has contents
                children = list(path.iterdir())
                if children:
                    perm_info = _check_file_permissions(path)
                    findings.append(
                        SecretFinding(
                            category=category,
                            path=str(path),
                            severity=config["severity"],
                            status="present",
                            detail=f"Directory with {len(children)} items. {perm_info}",
                        )
                    )
                continue

            # File exists — check details
            perm_info = _check_file_permissions(path)
            size = path.stat().st_size

            if category == "SSH Keys":
                encrypted = _check_ssh_key_encryption(path)
                status = "encrypted" if encrypted else "exposed"
                detail = f"{'Encrypted' if encrypted else 'UNENCRYPTED'} ({size} bytes). {perm_info}"
                rec = "" if encrypted else "Run: ssh-keygen -p -f " + str(path)
            elif category == "AWS Credentials" and path.name == "credentials":
                status, detail, rec = _check_aws_credentials(path, size, perm_info)
            elif path.suffix in (".json", ".yaml", ".yml", ".toml"):
                status = "exposed"
                detail = f"Plaintext config ({size} bytes). {perm_info}"
                rec = "Consider using a secret manager"
            elif path.suffix == ".db" or "keychain" in path.name:
                status = "system_protected"
                detail = f"System-managed database ({size} bytes). {perm_info}"
                rec = ""
            else:
                status = "present"
                detail = f"File exists ({size} bytes). {perm_info}"
                rec = ""

            findings.append(
                SecretFinding(
                    category=category,
                    path=str(path),
                    severity=config["severity"],
                    status=status,
                    detail=detail,
                    recommendation=rec,
                )
            )

    # Sort by severity
    severity_order = {"P0": 0, "P1": 1, "P2": 2}
    findings.sort(key=lambda x: severity_order.get(x.severity, 9))

    return findings
