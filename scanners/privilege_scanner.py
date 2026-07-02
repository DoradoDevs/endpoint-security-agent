"""
Sentinel Agent — Privilege Scanner

Checks for privilege escalation risks:
- Windows: UAC level, guest account, admin exposure
- macOS: Admin group membership, SIP status
- Linux: NOPASSWD sudoers, SUID/SGID binaries, world-writable PATH dirs
"""

from __future__ import annotations

import os
import platform
import subprocess
import stat
from pathlib import Path

from core.config import AgentConfig, ScanDepth, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


# Directories where SUID binaries are expected (Linux)
EXPECTED_SUID_DIRS = {
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
    "/bin", "/sbin", "/snap",
}


class PrivilegeScanner(BaseScanner):
    """Checks for privilege escalation risks and exposure."""

    @property
    def name(self) -> str:
        return "Privilege Scanner"

    @property
    def description(self) -> str:
        return "Detect privilege escalation risks and excessive permissions"

    def scan(self) -> list[Finding]:
        system = platform.system().lower()
        if system == "windows":
            return self._scan_windows()
        elif system == "darwin":
            return self._scan_macos()
        elif system == "linux":
            return self._scan_linux()
        return []

    def _scan_windows(self) -> list[Finding]:
        """Check Windows privilege escalation risks."""
        findings: list[Finding] = []

        # Check UAC level
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"
        ])
        if success and output.strip():
            try:
                uac_level = int(output.strip())
                # 0 = Elevate without prompting (most dangerous)
                # 1 = Prompt for credentials on secure desktop
                # 2 = Prompt for consent on secure desktop
                # 3 = Prompt for credentials
                # 4 = Prompt for consent
                # 5 = Prompt for consent for non-Windows binaries (default)
                if uac_level == 0:
                    findings.append(Finding(
                        title="UAC disabled: elevation without prompting",
                        description="User Account Control is set to never notify. "
                                    "This allows any program to elevate privileges silently.",
                        severity=Severity.CRITICAL,
                        category="Privilege Escalation",
                        scanner=self.name,
                        evidence={"ConsentPromptBehaviorAdmin": uac_level},
                        remediation="Set UAC to 'Always notify' in Control Panel > "
                                    "User Account Control Settings.",
                    ))
                elif uac_level < 5:
                    findings.append(Finding(
                        title="UAC set below recommended level",
                        description=f"UAC consent prompt level is {uac_level} "
                                    "(recommended: 5). Lower levels reduce elevation protection.",
                        severity=Severity.MEDIUM,
                        category="Privilege Escalation",
                        scanner=self.name,
                        evidence={"ConsentPromptBehaviorAdmin": uac_level},
                        remediation="Increase UAC level to maximum in Control Panel.",
                    ))
                else:
                    findings.append(Finding(
                        title="UAC at recommended level",
                        description="User Account Control is properly configured.",
                        severity=Severity.INFO,
                        category="Privilege Escalation",
                        scanner=self.name,
                        evidence={"ConsentPromptBehaviorAdmin": uac_level},
                        remediation="",
                    ))
            except ValueError:
                pass

        # Check if guest account is enabled
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
        ])
        if success and output.strip().lower() == "true":
            findings.append(Finding(
                title="Guest account is enabled",
                description="The Windows Guest account is active. This provides "
                            "unauthenticated access to the system.",
                severity=Severity.MEDIUM,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={"guest_enabled": True},
                remediation="Disable the Guest account: "
                            "net user Guest /active:no",
            ))

        # Check if current user is admin
        success, output = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        ])
        if success and output.strip().lower() == "true":
            findings.append(Finding(
                title="Running with administrator privileges",
                description="The current session has administrator privileges. "
                            "Day-to-day operations should use a standard user account.",
                severity=Severity.LOW,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={"is_admin": True},
                remediation="Use a standard user account for daily tasks. "
                            "Elevate only when needed.",
            ))

        return findings

    def _scan_macos(self) -> list[Finding]:
        """Check macOS privilege risks."""
        findings: list[Finding] = []

        # Check if current user is admin
        success, output = _run_cmd(["groups"])
        if success and "admin" in output.split():
            findings.append(Finding(
                title="Current user is in admin group",
                description="Your user account is in the admin group. "
                            "Consider using a standard account for daily use.",
                severity=Severity.LOW,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={"groups": output.split()},
                remediation="Create a standard user account for daily tasks.",
            ))

        # Check SIP status
        success, output = _run_cmd(["csrutil", "status"])
        if success:
            if "disabled" in output.lower():
                findings.append(Finding(
                    title="System Integrity Protection (SIP) is disabled",
                    description="SIP protects critical system files from modification. "
                                "Disabling it significantly weakens macOS security.",
                    severity=Severity.CRITICAL,
                    category="Privilege Escalation",
                    scanner=self.name,
                    evidence={"sip_status": output},
                    remediation="Re-enable SIP: Boot into Recovery Mode and run 'csrutil enable'.",
                ))
            else:
                findings.append(Finding(
                    title="System Integrity Protection enabled",
                    description="SIP is properly enabled.",
                    severity=Severity.INFO,
                    category="Privilege Escalation",
                    scanner=self.name,
                    evidence={"sip_status": output},
                    remediation="",
                ))

        return findings

    def _scan_linux(self) -> list[Finding]:
        """Check Linux privilege escalation risks."""
        findings: list[Finding] = []

        # Check sudoers for NOPASSWD
        findings.extend(self._check_nopasswd_sudoers())

        # Check for SUID/SGID binaries in unusual locations
        if self.config.scan.depth in (ScanDepth.STANDARD, ScanDepth.DEEP):
            findings.extend(self._check_suid_binaries())

        # Check for world-writable directories in PATH
        findings.extend(self._check_path_security())

        return findings

    def _check_nopasswd_sudoers(self) -> list[Finding]:
        """Check for NOPASSWD entries in sudoers configuration."""
        findings: list[Finding] = []
        nopasswd_entries: list[str] = []

        # Check main sudoers file
        sudoers_paths = ["/etc/sudoers"]
        sudoers_dir = Path("/etc/sudoers.d")
        if sudoers_dir.exists():
            try:
                sudoers_paths.extend(
                    str(f) for f in sudoers_dir.iterdir() if f.is_file()
                )
            except PermissionError:
                pass

        for spath in sudoers_paths:
            try:
                content = Path(spath).read_text(errors="replace")
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                        nopasswd_entries.append(f"{spath}: {stripped}")
            except (OSError, PermissionError):
                continue

        if nopasswd_entries:
            findings.append(Finding(
                title=f"NOPASSWD sudo entries found: {len(nopasswd_entries)}",
                description="Users or groups can execute commands as root without "
                            "entering a password. This weakens the privilege boundary.",
                severity=Severity.HIGH,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={
                    "nopasswd_count": len(nopasswd_entries),
                    "entries": nopasswd_entries[:10],
                },
                remediation="Remove NOPASSWD from sudoers entries where possible. "
                            "Limit NOPASSWD to specific, safe commands only.",
            ))

        return findings

    def _check_suid_binaries(self) -> list[Finding]:
        """Find SUID/SGID binaries in unusual locations."""
        findings: list[Finding] = []
        suspicious_suid: list[str] = []

        # Use find command with timeout to locate SUID binaries
        success, output = _run_cmd([
            "find", "/", "-perm", "-4000", "-type", "f",
            "-not", "-path", "*/proc/*",
            "-not", "-path", "*/snap/*",
        ], timeout=30)

        if success and output:
            for filepath in output.splitlines():
                filepath = filepath.strip()
                if not filepath:
                    continue

                # Check if this SUID binary is in an expected location
                parent = str(Path(filepath).parent)
                in_expected = any(parent.startswith(d) for d in EXPECTED_SUID_DIRS)

                if not in_expected:
                    suspicious_suid.append(filepath)

        if suspicious_suid:
            findings.append(Finding(
                title=f"SUID binaries in unusual locations: {len(suspicious_suid)}",
                description="Found SUID (set-user-ID) binaries outside standard system "
                            "directories. These could be used for privilege escalation.",
                severity=Severity.HIGH,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={
                    "suspicious_suid": suspicious_suid[:20],
                    "total": len(suspicious_suid),
                },
                remediation="Review each SUID binary. Remove the SUID bit from any "
                            "that don't need it: chmod u-s <file>",
            ))

        return findings

    def _check_path_security(self) -> list[Finding]:
        """Check for world-writable directories in PATH."""
        findings: list[Finding] = []
        writable_dirs: list[str] = []

        path_dirs = os.environ.get("PATH", "").split(":")
        for d in path_dirs:
            try:
                p = Path(d)
                if p.exists():
                    mode = p.stat().st_mode
                    if mode & stat.S_IWOTH:  # World-writable
                        writable_dirs.append(d)
            except (OSError, PermissionError):
                continue

        if writable_dirs:
            findings.append(Finding(
                title=f"World-writable directories in PATH: {len(writable_dirs)}",
                description="Directories in the system PATH are world-writable. "
                            "An attacker could place malicious binaries in these locations.",
                severity=Severity.HIGH,
                category="Privilege Escalation",
                scanner=self.name,
                evidence={"writable_dirs": writable_dirs},
                remediation="Remove world-writable permission from PATH directories: "
                            "chmod o-w <directory>",
            ))

        return findings
