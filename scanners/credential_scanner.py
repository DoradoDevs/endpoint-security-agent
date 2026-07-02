"""
Sentinel Agent — Credential Scanner

Detects exposed credentials, unprotected SSH keys, and secrets in
common configuration files and shell history.

SECURITY: This scanner NEVER reads or logs actual secret values.
It only reports the existence and location of potential exposures.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path

from core.config import AgentConfig, ScanDepth, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


# Patterns that indicate secrets (matched against file content line-by-line)
SECRET_PATTERNS = [
    (re.compile(r'(?:API_KEY|APIKEY|api_key)\s*[=:]\s*\S+', re.IGNORECASE), "API key"),
    (re.compile(r'(?:SECRET_KEY|SECRET|secret_key)\s*[=:]\s*\S+', re.IGNORECASE), "Secret key"),
    (re.compile(r'(?:PASSWORD|PASSWD|password|passwd)\s*[=:]\s*\S+', re.IGNORECASE), "Password"),
    (re.compile(r'(?:TOKEN|ACCESS_TOKEN|token)\s*[=:]\s*\S+', re.IGNORECASE), "Access token"),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r'(?:PRIVATE_KEY|private_key)\s*[=:]\s*\S+', re.IGNORECASE), "Private key reference"),
    (re.compile(r'(?:DB_PASSWORD|DATABASE_PASSWORD|db_pass)\s*[=:]\s*\S+', re.IGNORECASE), "Database password"),
    (re.compile(r'(?:GITHUB_TOKEN|GH_TOKEN)\s*[=:]\s*\S+', re.IGNORECASE), "GitHub token"),
]

# Files commonly containing credentials
CREDENTIAL_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".docker/config.json",
    ".kube/config",
]

# Cloud credential paths (relative to home)
CLOUD_CREDENTIAL_PATHS = [
    ".aws/credentials",
    ".aws/config",
    ".azure/accessTokens.json",
    ".config/gcloud/credentials.db",
    ".config/gcloud/application_default_credentials.json",
]

# Shell history files
SHELL_HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".python_history",
]


class CredentialScanner(BaseScanner):
    """Detects exposed credentials and secrets in common locations."""

    @property
    def name(self) -> str:
        return "Credential Scanner"

    @property
    def description(self) -> str:
        return "Detect exposed credentials, unprotected keys, and secrets"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        home = Path.home()

        # Check SSH keys
        findings.extend(self._check_ssh_keys(home))

        # Check credential files
        findings.extend(self._check_credential_files(home))

        # Check cloud credentials
        findings.extend(self._check_cloud_credentials(home))

        # Check shell history for secrets (deep scan only)
        if self.config.scan.depth == ScanDepth.DEEP:
            findings.extend(self._check_shell_history(home))

        return findings

    def _check_ssh_keys(self, home: Path) -> list[Finding]:
        """Check for SSH private keys without passphrase protection."""
        findings: list[Finding] = []
        ssh_dir = home / ".ssh"

        if not ssh_dir.exists():
            return findings

        try:
            key_files = []
            for f in ssh_dir.iterdir():
                if f.is_file() and not f.name.endswith(".pub") and f.name != "known_hosts" \
                        and f.name != "authorized_keys" and f.name != "config":
                    # Check if it looks like a private key
                    try:
                        header = f.read_bytes()[:50]
                        if b"PRIVATE KEY" in header or b"OPENSSH PRIVATE KEY" in header:
                            key_files.append(f)
                    except (OSError, PermissionError):
                        continue

            for key_file in key_files:
                # Check if key is encrypted (has passphrase)
                try:
                    content = key_file.read_bytes()
                    is_encrypted = b"ENCRYPTED" in content or b"Proc-Type: 4,ENCRYPTED" in content

                    # For OpenSSH format keys, check the encryption indicator
                    if b"OPENSSH PRIVATE KEY" in content and b"aes" not in content.lower():
                        # OpenSSH format — check bcrypt rounds (unencrypted has "none")
                        if b"none" in content[:200]:
                            is_encrypted = False

                    if not is_encrypted:
                        findings.append(Finding(
                            title=f"SSH private key without passphrase: {key_file.name}",
                            description=f"The SSH private key at ~/.ssh/{key_file.name} does not "
                                        "appear to be passphrase-protected. If this key is "
                                        "compromised, an attacker can use it immediately.",
                            severity=Severity.HIGH,
                            category="Credential Exposure",
                            scanner=self.name,
                            evidence={
                                "file": f"~/.ssh/{key_file.name}",
                                "encrypted": False,
                            },
                            remediation="Add a passphrase to this key: "
                                        f"ssh-keygen -p -f ~/.ssh/{key_file.name}",
                        ))
                    else:
                        findings.append(Finding(
                            title=f"SSH key protected: {key_file.name}",
                            description=f"SSH key ~/.ssh/{key_file.name} is passphrase-protected.",
                            severity=Severity.INFO,
                            category="Credential Exposure",
                            scanner=self.name,
                            evidence={
                                "file": f"~/.ssh/{key_file.name}",
                                "encrypted": True,
                            },
                            remediation="",
                        ))
                except (OSError, PermissionError):
                    continue

            # Check SSH key file permissions (Unix only)
            if platform.system().lower() != "windows":
                for key_file in key_files:
                    try:
                        mode = oct(key_file.stat().st_mode)[-3:]
                        if mode not in ("600", "400"):
                            findings.append(Finding(
                                title=f"SSH key has weak permissions: {key_file.name}",
                                description=f"~/.ssh/{key_file.name} has permissions {mode}. "
                                            "Private keys should be 600 or 400.",
                                severity=Severity.MEDIUM,
                                category="Credential Exposure",
                                scanner=self.name,
                                evidence={
                                    "file": f"~/.ssh/{key_file.name}",
                                    "permissions": mode,
                                },
                                remediation=f"Fix permissions: chmod 600 ~/.ssh/{key_file.name}",
                            ))
                    except OSError:
                        continue

        except (PermissionError, OSError):
            pass

        return findings

    def _check_credential_files(self, home: Path) -> list[Finding]:
        """Check for credential files containing secrets."""
        findings: list[Finding] = []

        for rel_path in CREDENTIAL_FILES:
            filepath = home / rel_path
            if not filepath.exists():
                continue

            try:
                content = filepath.read_text(errors="replace")
                secret_types_found: set[str] = set()

                for pattern, secret_type in SECRET_PATTERNS:
                    if pattern.search(content):
                        secret_types_found.add(secret_type)

                if secret_types_found:
                    findings.append(Finding(
                        title=f"Secrets found in ~/{rel_path}",
                        description=f"The file ~/{rel_path} contains potential credentials: "
                                    f"{', '.join(sorted(secret_types_found))}. "
                                    "These may be exposed if this file is shared or committed to version control.",
                        severity=Severity.HIGH,
                        category="Credential Exposure",
                        scanner=self.name,
                        evidence={
                            "file": f"~/{rel_path}",
                            "secret_types": sorted(secret_types_found),
                            # Deliberately NOT including actual values
                        },
                        remediation=f"Review ~/{rel_path} and ensure it is not committed to "
                                    "version control. Add it to .gitignore. Consider using a "
                                    "secrets manager instead of storing credentials in files.",
                    ))
            except (OSError, PermissionError):
                continue

        return findings

    def _check_cloud_credentials(self, home: Path) -> list[Finding]:
        """Check for cloud provider credential files."""
        findings: list[Finding] = []

        for rel_path in CLOUD_CREDENTIAL_PATHS:
            filepath = home / rel_path
            if filepath.exists():
                findings.append(Finding(
                    title=f"Cloud credentials found: ~/{rel_path}",
                    description=f"Cloud provider credentials exist at ~/{rel_path}. "
                                "Ensure these credentials have minimal required permissions "
                                "and are rotated regularly.",
                    severity=Severity.MEDIUM,
                    category="Credential Exposure",
                    scanner=self.name,
                    evidence={
                        "file": f"~/{rel_path}",
                        "provider": self._detect_cloud_provider(rel_path),
                    },
                    remediation="Review cloud credential permissions. Use IAM roles or "
                                "temporary credentials where possible. Rotate keys regularly.",
                ))

        return findings

    def _detect_cloud_provider(self, path: str) -> str:
        if ".aws" in path:
            return "AWS"
        elif ".azure" in path:
            return "Azure"
        elif "gcloud" in path:
            return "Google Cloud"
        return "Unknown"

    def _check_shell_history(self, home: Path) -> list[Finding]:
        """Check shell history for accidentally typed secrets."""
        findings: list[Finding] = []

        for hist_file in SHELL_HISTORY_FILES:
            filepath = home / hist_file
            if not filepath.exists():
                continue

            try:
                # Only check last 1000 lines to keep scan fast
                lines = filepath.read_text(errors="replace").splitlines()[-1000:]
                secret_indicators = 0

                for line in lines:
                    for pattern, _ in SECRET_PATTERNS:
                        if pattern.search(line):
                            secret_indicators += 1
                            break  # One match per line is enough

                if secret_indicators > 0:
                    findings.append(Finding(
                        title=f"Potential secrets in shell history: {hist_file}",
                        description=f"Found {secret_indicators} line(s) in ~/{hist_file} "
                                    "that may contain credentials or secrets typed in the terminal.",
                        severity=Severity.LOW,
                        category="Credential Exposure",
                        scanner=self.name,
                        evidence={
                            "file": f"~/{hist_file}",
                            "suspicious_lines": secret_indicators,
                        },
                        remediation=f"Review and clean ~/{hist_file}. "
                                    "Avoid typing secrets directly in the terminal. "
                                    "Use environment variables or credential managers.",
                    ))
            except (OSError, PermissionError):
                continue

        return findings
