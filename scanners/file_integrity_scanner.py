"""
Sentinel Agent — File Integrity Scanner

Monitors critical system files via SHA-256 hashing. Detects unauthorized
modifications by comparing current hashes against a stored baseline.

First run creates the baseline. Subsequent runs detect changes.
"""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path

from core.config import AgentConfig, ScanDepth, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


# Critical files per platform — files whose modification may indicate compromise
CRITICAL_FILES_WINDOWS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
    r"C:\Windows\System32\config\SECURITY",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\taskmgr.exe",
    r"C:\Windows\System32\net.exe",
    r"C:\Windows\System32\netsh.exe",
    r"C:\Windows\System32\sc.exe",
    r"C:\Windows\System32\reg.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
]

CRITICAL_FILES_MACOS = [
    "/etc/hosts",
    "/etc/sudoers",
    "/etc/pam.d/sudo",
    "/etc/ssh/sshd_config",
    "/etc/shells",
    "/etc/passwd",
    "/etc/group",
    "/usr/bin/sudo",
    "/usr/bin/login",
    "/usr/bin/su",
    "/usr/sbin/sshd",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchDaemons",
]

CRITICAL_FILES_LINUX = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/sudo",
    "/etc/pam.d/sshd",
    "/etc/crontab",
    "/etc/shells",
    "/etc/ld.so.conf",
    "/etc/ld.so.preload",
    "/etc/environment",
    "/etc/profile",
    "/etc/security/limits.conf",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/sbin/sshd",
    "/usr/sbin/cron",
]


def _baseline_dir() -> Path:
    """Get the baseline storage directory."""
    system = platform.system().lower()
    if system == "windows":
        return Path.home() / "AppData" / "Local" / "Sentinel" / "baselines"
    elif system == "darwin":
        return Path.home() / "Library" / "Application Support" / "Sentinel" / "baselines"
    else:
        return Path.home() / ".sentinel" / "baselines"


def _hash_file(path: str) -> str | None:
    """Compute SHA-256 hash of a file. Returns None if file is unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class FileIntegrityScanner(BaseScanner):
    """Monitors integrity of critical system files via cryptographic hashes."""

    @property
    def name(self) -> str:
        return "File Integrity Scanner"

    @property
    def description(self) -> str:
        return "Monitor critical system files for unauthorized modifications"

    def _get_critical_files(self) -> list[str]:
        """Get list of critical files for the current platform."""
        system = platform.system().lower()
        if system == "windows":
            files = list(CRITICAL_FILES_WINDOWS)
        elif system == "darwin":
            files = list(CRITICAL_FILES_MACOS)
        else:
            files = list(CRITICAL_FILES_LINUX)

        # Depth controls how many files we check
        if self.config.scan.depth == ScanDepth.QUICK:
            return files[:8]
        elif self.config.scan.depth == ScanDepth.STANDARD:
            return files
        else:  # DEEP — include extended paths
            return files

    def _load_baseline(self) -> dict[str, str]:
        """Load stored baseline hashes."""
        baseline_file = _baseline_dir() / "file_hashes.json"
        if baseline_file.exists():
            try:
                return json.loads(baseline_file.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_baseline(self, hashes: dict[str, str]) -> None:
        """Save current hashes as the new baseline."""
        baseline_file = _baseline_dir() / "file_hashes.json"
        baseline_file.parent.mkdir(parents=True, exist_ok=True)
        baseline_file.write_text(json.dumps(hashes, indent=2))

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        critical_files = self._get_critical_files()

        # Compute current hashes
        current_hashes: dict[str, str] = {}
        unreadable: list[str] = []
        for filepath in critical_files:
            h = _hash_file(filepath)
            if h is not None:
                current_hashes[filepath] = h
            else:
                unreadable.append(filepath)

        # Load baseline
        baseline = self._load_baseline()

        if not baseline:
            # First run — create baseline
            self._save_baseline(current_hashes)
            findings.append(Finding(
                title="File integrity baseline created",
                description=f"Initial baseline created for {len(current_hashes)} critical system files. "
                            "Future scans will detect modifications.",
                severity=Severity.INFO,
                category="File Integrity",
                scanner=self.name,
                evidence={"files_baselined": len(current_hashes)},
                remediation="",
            ))
            return findings

        # Compare against baseline
        modified_files: list[str] = []
        new_files: list[str] = []
        missing_files: list[str] = []

        for filepath, current_hash in current_hashes.items():
            if filepath in baseline:
                if baseline[filepath] != current_hash:
                    modified_files.append(filepath)
            else:
                new_files.append(filepath)

        for filepath in baseline:
            if filepath not in current_hashes and filepath not in unreadable:
                missing_files.append(filepath)

        # Report modified files
        for filepath in modified_files:
            findings.append(Finding(
                title=f"Critical file modified: {Path(filepath).name}",
                description=f"The file {filepath} has been modified since the last baseline scan. "
                            "This could indicate unauthorized system changes or compromise.",
                severity=Severity.HIGH,
                category="File Integrity",
                scanner=self.name,
                evidence={
                    "file": filepath,
                    "baseline_hash": baseline.get(filepath, "unknown"),
                    "current_hash": current_hashes[filepath],
                },
                remediation="Investigate the file modification. Compare against known-good versions. "
                            "If expected (e.g., system update), re-run scan to update baseline.",
            ))

        # Report missing critical files
        for filepath in missing_files:
            findings.append(Finding(
                title=f"Critical file missing: {Path(filepath).name}",
                description=f"The file {filepath} was present in the baseline but is now missing. "
                            "This could indicate tampering or system damage.",
                severity=Severity.CRITICAL,
                category="File Integrity",
                scanner=self.name,
                evidence={"file": filepath, "status": "missing"},
                remediation="Investigate why the critical system file is missing. "
                            "Restore from backup or reinstall affected component.",
            ))

        # Summary finding
        if not modified_files and not missing_files:
            findings.append(Finding(
                title="File integrity check passed",
                description=f"All {len(current_hashes)} monitored files match their baseline hashes.",
                severity=Severity.INFO,
                category="File Integrity",
                scanner=self.name,
                evidence={"files_checked": len(current_hashes), "status": "clean"},
                remediation="",
            ))

        # Update baseline with current hashes
        self._save_baseline(current_hashes)

        return findings
