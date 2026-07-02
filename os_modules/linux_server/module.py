"""
Sentinel Agent — Linux Server OS Module

Interrogates Linux security state for server environments.
Supports Ubuntu LTS, Debian, and RHEL-compatible distributions.
All operations are read-only.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from core.logging import get_logger
from os_modules.base import (
    BaseOSModule,
    FirewallStatus,
    EncryptionStatus,
    UpdateStatus,
    SecureBootStatus,
    StartupEntry,
    ServiceInfo,
)


def _run_cmd(args: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        get_logger().debug(f"Command failed {args[0]}: {e}")
        return ""


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError):
        return ""


def _detect_distro() -> str:
    """Detect Linux distribution family."""
    os_release = _read_file("/etc/os-release")
    lower = os_release.lower()
    if "ubuntu" in lower or "debian" in lower:
        return "debian"
    elif "rhel" in lower or "centos" in lower or "fedora" in lower or "rocky" in lower or "alma" in lower:
        return "rhel"
    elif "suse" in lower:
        return "suse"
    return "unknown"


class LinuxServerModule(BaseOSModule):

    def __init__(self):
        self.distro = _detect_distro()

    @property
    def platform_name(self) -> str:
        return "linux"

    def get_firewall_status(self) -> FirewallStatus:
        # Try ufw first (Ubuntu/Debian)
        ufw_output = _run_cmd(["ufw", "status"])
        if ufw_output and "status:" in ufw_output.lower():
            ufw_active = "status: active" in ufw_output.lower() and "inactive" not in ufw_output.lower()
            lines = ufw_output.strip().splitlines()
            return FirewallStatus(
                enabled=ufw_active,
                details=f"UFW: {'active' if ufw_active else 'inactive'} ({len(lines) - 1} rules visible)",
                rules_count=max(0, len(lines) - 4) if ufw_active else 0,
                extra={"backend": "ufw", "output": ufw_output[:2000]},
            )

        # Try firewalld (RHEL/CentOS)
        fwd_output = _run_cmd(["firewall-cmd", "--state"])
        if fwd_output and "running" in fwd_output.lower():
            zones = _run_cmd(["firewall-cmd", "--list-all-zones"])
            return FirewallStatus(
                enabled=True,
                details="firewalld: running",
                extra={"backend": "firewalld", "zones": zones[:2000]},
            )

        # Try iptables
        ipt_output = _run_cmd(["iptables", "-L", "-n", "--line-numbers"])
        if ipt_output:
            rule_count = sum(1 for line in ipt_output.splitlines() if line and not line.startswith(("Chain", "num")))
            return FirewallStatus(
                enabled=rule_count > 0,
                details=f"iptables: {rule_count} rules",
                rules_count=rule_count,
                extra={"backend": "iptables"},
            )

        return FirewallStatus(enabled=False, details="No firewall detected (ufw/firewalld/iptables)")

    def get_encryption_status(self) -> EncryptionStatus:
        # Check LUKS
        lsblk = _run_cmd(["lsblk", "-o", "NAME,TYPE,FSTYPE", "--json"])
        if lsblk and "crypt" in lsblk.lower():
            return EncryptionStatus(enabled=True, method="LUKS", details="LUKS encrypted volumes detected")

        dmsetup = _run_cmd(["dmsetup", "status"])
        if dmsetup and "crypt" in dmsetup.lower():
            return EncryptionStatus(enabled=True, method="dm-crypt", details="dm-crypt volumes active")

        return EncryptionStatus(enabled=False, details="No disk encryption detected")

    def get_update_status(self) -> UpdateStatus:
        if self.distro == "debian":
            # Check unattended-upgrades
            auto = Path("/etc/apt/apt.conf.d/20auto-upgrades").exists()
            pending_output = _run_cmd(["apt", "list", "--upgradable"], timeout=60)
            pending = max(0, len(pending_output.splitlines()) - 1) if pending_output else 0
            return UpdateStatus(
                auto_updates_enabled=auto,
                pending_updates=pending,
                details=f"apt: {pending} upgradable | auto-updates: {'configured' if auto else 'not configured'}",
            )
        elif self.distro == "rhel":
            auto = _run_cmd(["systemctl", "is-enabled", "dnf-automatic.timer"])
            auto_enabled = "enabled" in auto.lower() if auto else False
            pending_output = _run_cmd(["dnf", "check-update", "--quiet"], timeout=60)
            pending = len([l for l in pending_output.splitlines() if l.strip()]) if pending_output else 0
            return UpdateStatus(
                auto_updates_enabled=auto_enabled,
                pending_updates=pending,
                details=f"dnf: {pending} upgradable | auto-updates: {'enabled' if auto_enabled else 'disabled'}",
            )

        return UpdateStatus(details="Unknown package manager")

    def get_secure_boot_status(self) -> SecureBootStatus:
        mokutil = _run_cmd(["mokutil", "--sb-state"])
        if mokutil:
            enabled = "secureboot enabled" in mokutil.lower()
            return SecureBootStatus(supported=True, enabled=enabled, details=mokutil)
        # Fallback: check EFI variable
        sb_var = _read_file("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        if sb_var:
            return SecureBootStatus(supported=True, enabled=True, details="Secure Boot variable present")
        return SecureBootStatus(supported=False, details="Secure Boot not detected (legacy BIOS?)")

    def get_startup_entries(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []

        # Systemd enabled services
        output = _run_cmd(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
        if output:
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "enabled":
                    entries.append(StartupEntry(
                        name=parts[0],
                        command=f"systemd: {parts[0]}",
                        location="systemd",
                        enabled=True,
                    ))

        # Cron jobs
        for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"]:
            cron_path = Path(cron_dir)
            if cron_path.exists():
                for f in cron_path.iterdir():
                    if f.is_file() and not f.name.startswith("."):
                        entries.append(StartupEntry(
                            name=f.name,
                            command=f"cron: {cron_dir}/{f.name}",
                            location=cron_dir,
                        ))

        # User crontab
        crontab = _run_cmd(["crontab", "-l"])
        if crontab and "no crontab" not in crontab.lower():
            for line in crontab.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(StartupEntry(
                        name=f"crontab: {line[:50]}",
                        command=line,
                        location="user_crontab",
                    ))

        return entries

    def get_running_services(self) -> list[ServiceInfo]:
        output = _run_cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
        services: list[ServiceInfo] = []
        if not output:
            return services

        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append(ServiceInfo(
                    name=parts[0],
                    display_name=" ".join(parts[4:]) if len(parts) > 4 else parts[0],
                    status="running",
                    start_type="systemd",
                ))

        return services

    def get_admin_users(self) -> list[str]:
        """Get users in sudo/wheel group."""
        users: list[str] = []
        # Check sudo group (Debian/Ubuntu)
        output = _run_cmd(["getent", "group", "sudo"])
        if output and ":" in output:
            members = output.split(":")[-1]
            users.extend(m.strip() for m in members.split(",") if m.strip())
        # Check wheel group (RHEL)
        output = _run_cmd(["getent", "group", "wheel"])
        if output and ":" in output:
            members = output.split(":")[-1]
            users.extend(m.strip() for m in members.split(",") if m.strip())
        # root is always admin
        if "root" not in users:
            users.insert(0, "root")
        return users

    def get_password_policy(self) -> dict[str, Any]:
        policy: dict[str, Any] = {}

        # /etc/login.defs
        login_defs = _read_file("/etc/login.defs")
        if login_defs:
            for line in login_defs.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in (
                        "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE",
                        "LOGIN_RETRIES", "LOGIN_TIMEOUT", "ENCRYPT_METHOD",
                    ):
                        policy[parts[0]] = parts[1]

        # Check pam password quality
        pam_pwquality = _read_file("/etc/security/pwquality.conf")
        if pam_pwquality:
            policy["pwquality_configured"] = True
            for line in pam_pwquality.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    policy[f"pwquality_{key.strip()}"] = val.strip()
        else:
            policy["pwquality_configured"] = False

        return policy

    def get_os_patch_level(self) -> dict[str, Any]:
        os_release = _read_file("/etc/os-release")
        kernel = _run_cmd(["uname", "-r"])
        return {
            "os_release": os_release[:1000],
            "kernel": kernel,
            "distro_family": self.distro,
        }

    # --- Linux Server-specific methods ---

    def get_ssh_config(self) -> dict[str, str]:
        """Parse SSH server configuration for security audit."""
        config: dict[str, str] = {}
        sshd_config = _read_file("/etc/ssh/sshd_config")
        if not sshd_config:
            return {"error": "Cannot read /etc/ssh/sshd_config"}

        for line in sshd_config.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0]] = parts[1]

        return config

    def get_open_ports(self) -> list[dict[str, Any]]:
        """Get listening ports using ss."""
        output = _run_cmd(["ss", "-tlnp"])
        ports: list[dict[str, Any]] = []
        if not output:
            return ports

        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                local_addr = parts[3]
                process = parts[-1] if "users:" in parts[-1] else ""
                ports.append({
                    "address": local_addr,
                    "process": process,
                    "state": parts[0] if parts else "LISTEN",
                })

        return ports

    def check_root_login(self) -> bool:
        """Check if direct root login is permitted."""
        ssh_config = self.get_ssh_config()
        permit_root = ssh_config.get("PermitRootLogin", "prohibit-password").lower()
        return permit_root in ("yes", "without-password", "prohibit-password")
