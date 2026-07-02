"""
Sentinel Agent — Configuration Scanner

Audits system security configuration:
- Disk encryption status
- Secure Boot/SIP status
- Admin privilege exposure
- Password policy strength
- SSH configuration (Linux server)
- Insecure protocol detection

Read-only analysis — no configuration changes.
"""

from __future__ import annotations

import platform

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from os_modules.loader import load_os_module
from scanners.base import BaseScanner


class ConfigScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "Configuration Scanner"

    @property
    def description(self) -> str:
        return "Audit system security configuration and hardening status"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        os_module = load_os_module()

        findings.extend(self._check_encryption(os_module))
        findings.extend(self._check_secure_boot(os_module))
        findings.extend(self._check_admin_exposure(os_module))
        findings.extend(self._check_password_policy(os_module))
        findings.extend(self._check_update_config(os_module))

        # Linux server-specific checks
        if platform.system().lower() == "linux" and self.config.scan.server_mode:
            findings.extend(self._check_ssh_config(os_module))
            findings.extend(self._check_linux_server(os_module))

        return findings

    def _check_encryption(self, os_module) -> list[Finding]:
        findings: list[Finding] = []
        enc = os_module.get_encryption_status()

        if not enc.enabled:
            findings.append(Finding(
                title="Disk encryption is not enabled",
                description=(
                    f"Full disk encryption is not active. {enc.details}. "
                    "Data at rest is vulnerable to physical access attacks."
                ),
                severity=Severity.HIGH,
                category="System Configuration",
                scanner=self.name,
                evidence={"method": enc.method, "details": enc.details},
                remediation=self._encryption_remediation(),
            ))
        else:
            findings.append(Finding(
                title=f"Disk encryption enabled: {enc.method}",
                description=f"Full disk encryption is active. {enc.details}",
                severity=Severity.INFO,
                category="System Configuration",
                scanner=self.name,
                evidence={"method": enc.method},
            ))

        return findings

    def _encryption_remediation(self) -> str:
        system = platform.system().lower()
        if system == "windows":
            return "Enable BitLocker via Control Panel > System and Security > BitLocker Drive Encryption."
        elif system == "darwin":
            return "Enable FileVault via System Preferences > Security & Privacy > FileVault."
        return "Configure LUKS encryption for sensitive volumes."

    def _check_secure_boot(self, os_module) -> list[Finding]:
        findings: list[Finding] = []
        sb = os_module.get_secure_boot_status()

        if sb.supported and not sb.enabled:
            findings.append(Finding(
                title="Secure Boot / SIP is disabled",
                description=f"Secure Boot protection is available but disabled. {sb.details}",
                severity=Severity.MEDIUM,
                category="System Configuration",
                scanner=self.name,
                evidence={"details": sb.details},
                remediation="Enable Secure Boot in UEFI/BIOS settings (or re-enable SIP on macOS).",
            ))
        elif sb.enabled:
            findings.append(Finding(
                title="Secure Boot / SIP is enabled",
                description=sb.details,
                severity=Severity.INFO,
                category="System Configuration",
                scanner=self.name,
            ))

        return findings

    def _check_admin_exposure(self, os_module) -> list[Finding]:
        findings: list[Finding] = []
        admin_users = os_module.get_admin_users()

        if len(admin_users) > 3:
            findings.append(Finding(
                title=f"Excessive admin accounts: {len(admin_users)} users",
                description=(
                    f"Found {len(admin_users)} admin/sudo users: {', '.join(admin_users[:10])}. "
                    "Excessive admin access increases the attack surface."
                ),
                severity=Severity.MEDIUM,
                category="Access Control",
                scanner=self.name,
                evidence={"admin_users": admin_users},
                remediation="Review admin accounts. Remove unnecessary admin privileges.",
            ))
        elif admin_users:
            findings.append(Finding(
                title=f"Admin accounts: {len(admin_users)} users",
                description=f"Admin users: {', '.join(admin_users)}",
                severity=Severity.INFO,
                category="Access Control",
                scanner=self.name,
                evidence={"admin_users": admin_users},
            ))

        return findings

    def _check_password_policy(self, os_module) -> list[Finding]:
        findings: list[Finding] = []
        policy = os_module.get_password_policy()

        if not policy:
            findings.append(Finding(
                title="Unable to retrieve password policy",
                description="Could not read password policy settings.",
                severity=Severity.LOW,
                category="Access Control",
                scanner=self.name,
            ))
            return findings

        system = platform.system().lower()

        if system == "linux":
            max_days = policy.get("PASS_MAX_DAYS", "99999")
            if max_days == "99999":
                findings.append(Finding(
                    title="Password expiration is not enforced",
                    description="PASS_MAX_DAYS is set to 99999 (effectively no expiration).",
                    severity=Severity.MEDIUM,
                    category="Access Control",
                    scanner=self.name,
                    evidence=policy,
                    remediation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs.",
                ))

            min_len = policy.get("PASS_MIN_LEN", "5")
            try:
                if int(min_len) < 8:
                    findings.append(Finding(
                        title=f"Weak minimum password length: {min_len}",
                        description=f"Minimum password length is only {min_len} characters.",
                        severity=Severity.MEDIUM,
                        category="Access Control",
                        scanner=self.name,
                        remediation="Increase PASS_MIN_LEN to at least 12 in /etc/login.defs.",
                    ))
            except ValueError:
                pass

            if not policy.get("pwquality_configured"):
                findings.append(Finding(
                    title="Password quality rules not configured",
                    description="pwquality (pam_pwquality) is not configured for password complexity.",
                    severity=Severity.MEDIUM,
                    category="Access Control",
                    scanner=self.name,
                    remediation="Install and configure libpam-pwquality.",
                ))

        elif system == "windows":
            min_pw_len = policy.get("Minimum password length", "0")
            try:
                if int(min_pw_len) < 8:
                    findings.append(Finding(
                        title=f"Weak minimum password length: {min_pw_len}",
                        description=f"Windows minimum password length is only {min_pw_len} characters.",
                        severity=Severity.MEDIUM,
                        category="Access Control",
                        scanner=self.name,
                        remediation="Set minimum password length to at least 12 via Group Policy.",
                    ))
            except ValueError:
                pass

        return findings

    def _check_update_config(self, os_module) -> list[Finding]:
        findings: list[Finding] = []
        updates = os_module.get_update_status()

        if not updates.auto_updates_enabled:
            findings.append(Finding(
                title="Automatic updates are disabled",
                description=f"Automatic updates are not enabled. {updates.details}",
                severity=Severity.HIGH,
                category="Patch Management",
                scanner=self.name,
                remediation="Enable automatic updates to receive critical security patches.",
            ))

        return findings

    def _check_ssh_config(self, os_module) -> list[Finding]:
        """Linux server SSH hardening checks."""
        findings: list[Finding] = []

        if not hasattr(os_module, "get_ssh_config"):
            return findings

        ssh_config = os_module.get_ssh_config()
        if "error" in ssh_config:
            findings.append(Finding(
                title="Cannot read SSH configuration",
                description=ssh_config["error"],
                severity=Severity.LOW,
                category="SSH Security",
                scanner=self.name,
            ))
            return findings

        # Root login check
        permit_root = ssh_config.get("PermitRootLogin", "prohibit-password").lower()
        if permit_root == "yes":
            findings.append(Finding(
                title="SSH root login with password is permitted",
                description="PermitRootLogin is set to 'yes', allowing direct root login with a password.",
                severity=Severity.CRITICAL,
                category="SSH Security",
                scanner=self.name,
                remediation="Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in sshd_config.",
            ))

        # Password authentication
        pw_auth = ssh_config.get("PasswordAuthentication", "yes").lower()
        if pw_auth == "yes":
            findings.append(Finding(
                title="SSH password authentication is enabled",
                description="Password-based SSH authentication is enabled. Key-based auth is more secure.",
                severity=Severity.MEDIUM,
                category="SSH Security",
                scanner=self.name,
                remediation="Set 'PasswordAuthentication no' and use SSH keys.",
            ))

        # Protocol version
        protocol = ssh_config.get("Protocol", "2")
        if "1" in protocol:
            findings.append(Finding(
                title="SSH Protocol 1 is enabled",
                description="SSHv1 is known to have vulnerabilities. Only SSHv2 should be used.",
                severity=Severity.CRITICAL,
                category="SSH Security",
                scanner=self.name,
                remediation="Set 'Protocol 2' in sshd_config.",
            ))

        # Empty passwords
        empty_pw = ssh_config.get("PermitEmptyPasswords", "no").lower()
        if empty_pw == "yes":
            findings.append(Finding(
                title="SSH permits empty passwords",
                description="Empty password authentication is allowed. This is extremely dangerous.",
                severity=Severity.CRITICAL,
                category="SSH Security",
                scanner=self.name,
                remediation="Set 'PermitEmptyPasswords no' in sshd_config.",
            ))

        # X11 forwarding
        x11 = ssh_config.get("X11Forwarding", "no").lower()
        if x11 == "yes":
            findings.append(Finding(
                title="SSH X11 forwarding is enabled",
                description="X11 forwarding can be exploited on servers. Disable if not needed.",
                severity=Severity.LOW,
                category="SSH Security",
                scanner=self.name,
                remediation="Set 'X11Forwarding no' in sshd_config.",
            ))

        # MaxAuthTries
        max_tries = ssh_config.get("MaxAuthTries", "6")
        try:
            if int(max_tries) > 5:
                findings.append(Finding(
                    title=f"SSH MaxAuthTries is high: {max_tries}",
                    description=f"MaxAuthTries is set to {max_tries}. Lower values reduce brute-force risk.",
                    severity=Severity.LOW,
                    category="SSH Security",
                    scanner=self.name,
                    remediation="Set 'MaxAuthTries 3' in sshd_config.",
                ))
        except ValueError:
            pass

        return findings

    def _check_linux_server(self, os_module) -> list[Finding]:
        """Additional Linux server hardening checks."""
        findings: list[Finding] = []

        if not hasattr(os_module, "get_open_ports"):
            return findings

        # Open ports check
        ports = os_module.get_open_ports()
        if ports:
            findings.append(Finding(
                title=f"Server has {len(ports)} listening ports",
                description=f"Listening ports: {', '.join(p['address'] for p in ports[:20])}",
                severity=Severity.INFO,
                category="Server Security",
                scanner=self.name,
                evidence={"ports": ports[:30]},
                remediation="Review all listening ports and close unnecessary ones.",
            ))

        return findings
