"""
Sentinel Agent — Linux Hardening Actions

All Linux-specific hardening actions. Aligned with CIS benchmarks
and DISA STIGs for Linux server hardening.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from remediation.hardening import HardeningAction


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return False, str(e)


def _read_file(path: str) -> str | None:
    try:
        return Path(path).read_text()
    except (OSError, PermissionError):
        return None


def _modify_sshd_config(key: str, value: str) -> tuple[bool, str]:
    """Safely modify a key in sshd_config and reload SSH."""
    config_path = "/etc/ssh/sshd_config"
    content = _read_file(config_path)
    if content is None:
        return False, "Cannot read sshd_config"

    lines = content.splitlines()
    new_lines = []
    found = False
    for line in lines:
        if line.strip().startswith(key) and not line.strip().startswith("#"):
            new_lines.append(f"{key} {value}")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key} {value}")

    try:
        with open(config_path, "w") as f:
            f.write("\n".join(new_lines) + "\n")
        _run_cmd(["systemctl", "reload", "sshd"])
        return True, f"{key} set to '{value}' and SSH reloaded"
    except (OSError, PermissionError) as e:
        return False, str(e)


def get_linux_actions(config) -> list[HardeningAction]:
    """Return all Linux hardening actions."""
    engine = _LinuxHardening()
    return engine.actions()


class _LinuxHardening:
    """Linux hardening action definitions."""

    def actions(self) -> list[HardeningAction]:
        return [
            # === Original v1.0 actions ===
            HardeningAction(
                name="Enable UFW Firewall",
                description="Enable Uncomplicated Firewall with default deny incoming",
                severity="critical",
                check_fn=self._check_ufw,
                apply_fn=self._enable_ufw,
                platform="linux",
            ),
            HardeningAction(
                name="Disable SSH Root Login",
                description="Set PermitRootLogin to 'no' in SSH configuration",
                severity="critical",
                check_fn=self._check_ssh_root,
                apply_fn=self._disable_ssh_root,
                platform="linux",
            ),
            HardeningAction(
                name="Enable Automatic Security Updates",
                description="Install and enable unattended-upgrades (Debian/Ubuntu)",
                severity="high",
                check_fn=self._check_auto_updates,
                apply_fn=self._enable_auto_updates,
                platform="linux",
            ),
            HardeningAction(
                name="Disable SSH Password Authentication",
                description="Enforce key-based SSH authentication",
                severity="medium",
                check_fn=self._check_ssh_password,
                apply_fn=self._disable_ssh_password,
                platform="linux",
            ),
            # === New v2.0 actions ===
            HardeningAction(
                name="Install and Configure Fail2ban",
                description="Install fail2ban to auto-block repeated failed login attempts",
                severity="high",
                check_fn=self._check_fail2ban,
                apply_fn=self._install_fail2ban,
                platform="linux",
            ),
            HardeningAction(
                name="Enable AppArmor Enforcement",
                description="Ensure AppArmor is running with profiles enforced",
                severity="high",
                check_fn=self._check_apparmor,
                apply_fn=self._enable_apparmor,
                platform="linux",
            ),
            HardeningAction(
                name="Configure Audit Logging (auditd)",
                description="Install and enable auditd for comprehensive system auditing",
                severity="medium",
                check_fn=self._check_auditd,
                apply_fn=self._install_auditd,
                platform="linux",
            ),
            HardeningAction(
                name="Apply Kernel Hardening (sysctl)",
                description="Set recommended kernel security parameters via sysctl",
                severity="high",
                check_fn=self._check_kernel_hardening,
                apply_fn=self._apply_kernel_hardening,
                platform="linux",
            ),
            HardeningAction(
                name="Harden File Permissions",
                description="Restrict permissions on /etc/passwd, /etc/shadow, /etc/group",
                severity="medium",
                check_fn=self._check_file_permissions,
                apply_fn=self._fix_file_permissions,
                platform="linux",
            ),
            HardeningAction(
                name="Disable SSH Empty Passwords",
                description="Ensure empty passwords cannot be used for SSH authentication",
                severity="critical",
                check_fn=self._check_ssh_empty_passwords,
                apply_fn=self._disable_ssh_empty_passwords,
                platform="linux",
            ),
            HardeningAction(
                name="Set SSH MaxAuthTries",
                description="Limit SSH authentication attempts to prevent brute force",
                severity="medium",
                check_fn=self._check_ssh_max_auth,
                apply_fn=self._set_ssh_max_auth,
                platform="linux",
            ),
        ]

    # === UFW ===
    def _check_ufw(self) -> tuple[bool, str]:
        success, output = _run_cmd(["ufw", "status"])
        if success and "inactive" in output.lower():
            return True, "UFW firewall is inactive"
        if not success:
            return True, "UFW is not installed"
        return False, "UFW is active"

    def _enable_ufw(self) -> tuple[bool, str]:
        _run_cmd(["ufw", "allow", "ssh"])
        _run_cmd(["ufw", "default", "deny", "incoming"])
        _run_cmd(["ufw", "default", "allow", "outgoing"])
        return _run_cmd(["ufw", "--force", "enable"])

    # === SSH Root Login ===
    def _check_ssh_root(self) -> tuple[bool, str]:
        content = _read_file("/etc/ssh/sshd_config")
        if content is None:
            return False, "Cannot read sshd_config"
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("PermitRootLogin") and not stripped.startswith("#"):
                val = stripped.split(None, 1)[1].lower() if len(stripped.split()) > 1 else ""
                if val == "yes":
                    return True, "PermitRootLogin is set to 'yes'"
                return False, f"PermitRootLogin is '{val}'"
        return True, "PermitRootLogin not explicitly set (defaults may allow it)"

    def _disable_ssh_root(self) -> tuple[bool, str]:
        return _modify_sshd_config("PermitRootLogin", "no")

    # === Auto Updates ===
    def _check_auto_updates(self) -> tuple[bool, str]:
        if not Path("/etc/apt/apt.conf.d/20auto-upgrades").exists():
            return True, "Unattended-upgrades not configured"
        return False, "Auto-updates configured"

    def _enable_auto_updates(self) -> tuple[bool, str]:
        s1 = _run_cmd(["apt", "install", "-y", "unattended-upgrades"])
        if s1[0]:
            config = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
            try:
                with open("/etc/apt/apt.conf.d/20auto-upgrades", "w") as f:
                    f.write(config)
                return True, "Unattended-upgrades installed and configured"
            except OSError as e:
                return False, str(e)
        return False, "Failed to install unattended-upgrades"

    # === SSH Password Auth ===
    def _check_ssh_password(self) -> tuple[bool, str]:
        content = _read_file("/etc/ssh/sshd_config")
        if content is None:
            return False, "Cannot read sshd_config"
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("PasswordAuthentication") and not stripped.startswith("#"):
                val = stripped.split(None, 1)[1].lower() if len(stripped.split()) > 1 else ""
                if val == "yes":
                    return True, "SSH password authentication is enabled"
                return False, "SSH password authentication is disabled"
        return True, "PasswordAuthentication not set (defaults to yes)"

    def _disable_ssh_password(self) -> tuple[bool, str]:
        return _modify_sshd_config("PasswordAuthentication", "no")

    # === Fail2ban ===
    def _check_fail2ban(self) -> tuple[bool, str]:
        success, output = _run_cmd(["systemctl", "is-active", "fail2ban"])
        if success and "active" in output.lower():
            return False, "Fail2ban is running"
        return True, "Fail2ban is not active or installed"

    def _install_fail2ban(self) -> tuple[bool, str]:
        # Try apt first (Debian/Ubuntu), then dnf (RHEL)
        s1, _ = _run_cmd(["apt", "install", "-y", "fail2ban"], timeout=120)
        if not s1:
            s1, _ = _run_cmd(["dnf", "install", "-y", "fail2ban"], timeout=120)
        if not s1:
            return False, "Failed to install fail2ban"

        # Create basic jail config
        jail_config = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
"""
        try:
            with open("/etc/fail2ban/jail.local", "w") as f:
                f.write(jail_config)
        except OSError:
            pass

        _run_cmd(["systemctl", "enable", "fail2ban"])
        s2, msg = _run_cmd(["systemctl", "start", "fail2ban"])
        return s2, "Fail2ban installed, configured, and started"

    # === AppArmor ===
    def _check_apparmor(self) -> tuple[bool, str]:
        success, output = _run_cmd(["aa-status", "--enabled"])
        if success:
            return False, "AppArmor is enabled"
        # Check if apparmor is available but not enforcing
        s2, o2 = _run_cmd(["systemctl", "is-active", "apparmor"])
        if s2 and "active" in o2.lower():
            return False, "AppArmor service is running"
        return True, "AppArmor is not active"

    def _enable_apparmor(self) -> tuple[bool, str]:
        _run_cmd(["apt", "install", "-y", "apparmor", "apparmor-utils"], timeout=120)
        _run_cmd(["systemctl", "enable", "apparmor"])
        s, msg = _run_cmd(["systemctl", "start", "apparmor"])
        # Enforce all loaded profiles
        _run_cmd(["aa-enforce", "/etc/apparmor.d/*"])
        return s, "AppArmor installed and enforcement enabled"

    # === Auditd ===
    def _check_auditd(self) -> tuple[bool, str]:
        success, output = _run_cmd(["systemctl", "is-active", "auditd"])
        if success and "active" in output.lower():
            return False, "Audit daemon is running"
        return True, "Audit daemon is not active"

    def _install_auditd(self) -> tuple[bool, str]:
        s1, _ = _run_cmd(["apt", "install", "-y", "auditd", "audispd-plugins"], timeout=120)
        if not s1:
            s1, _ = _run_cmd(["dnf", "install", "-y", "audit"], timeout=120)
        if not s1:
            return False, "Failed to install auditd"

        _run_cmd(["systemctl", "enable", "auditd"])
        s2, msg = _run_cmd(["systemctl", "start", "auditd"])
        return s2, "Audit daemon installed and started"

    # === Kernel Hardening ===
    def _check_kernel_hardening(self) -> tuple[bool, str]:
        sysctl_file = Path("/etc/sysctl.d/99-sentinel-hardening.conf")
        if sysctl_file.exists():
            return False, "Sentinel kernel hardening rules are applied"
        # Check a key parameter
        success, output = _run_cmd(["sysctl", "net.ipv4.conf.all.rp_filter"])
        if success and "= 1" in output:
            return False, "Key kernel parameters appear hardened"
        return True, "Kernel hardening parameters not fully applied"

    def _apply_kernel_hardening(self) -> tuple[bool, str]:
        hardening_rules = """# Sentinel Security Agent — Kernel Hardening
# CIS Benchmark-aligned sysctl parameters

# Network hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1

# IPv6 hardening
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# Kernel hardening
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
fs.suid_dumpable = 0
"""
        try:
            with open("/etc/sysctl.d/99-sentinel-hardening.conf", "w") as f:
                f.write(hardening_rules)
            _run_cmd(["sysctl", "--system"])
            return True, "Kernel hardening parameters applied via sysctl"
        except (OSError, PermissionError) as e:
            return False, str(e)

    # === File Permissions ===
    def _check_file_permissions(self) -> tuple[bool, str]:
        import os
        import stat
        files_to_check = {
            "/etc/passwd": 0o644,
            "/etc/shadow": 0o640,
            "/etc/group": 0o644,
            "/etc/gshadow": 0o640,
        }
        issues = []
        for filepath, expected_mode in files_to_check.items():
            try:
                current_mode = os.stat(filepath).st_mode & 0o777
                if current_mode > expected_mode:
                    issues.append(f"{filepath}: {oct(current_mode)} (should be {oct(expected_mode)})")
            except OSError:
                pass

        if issues:
            return True, f"File permission issues: {'; '.join(issues)}"
        return False, "File permissions are correct"

    def _fix_file_permissions(self) -> tuple[bool, str]:
        fixes = [
            (["chmod", "644", "/etc/passwd"], "/etc/passwd"),
            (["chmod", "640", "/etc/shadow"], "/etc/shadow"),
            (["chmod", "644", "/etc/group"], "/etc/group"),
            (["chmod", "640", "/etc/gshadow"], "/etc/gshadow"),
            (["chown", "root:root", "/etc/passwd"], None),
            (["chown", "root:shadow", "/etc/shadow"], None),
        ]
        all_ok = True
        for cmd, _ in fixes:
            s, _ = _run_cmd(cmd)
            if not s:
                all_ok = False
        return all_ok, "File permissions hardened for /etc/passwd, /etc/shadow, /etc/group"

    # === SSH Empty Passwords ===
    def _check_ssh_empty_passwords(self) -> tuple[bool, str]:
        content = _read_file("/etc/ssh/sshd_config")
        if content is None:
            return False, "Cannot read sshd_config"
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("PermitEmptyPasswords") and not stripped.startswith("#"):
                val = stripped.split(None, 1)[1].lower() if len(stripped.split()) > 1 else ""
                if val == "yes":
                    return True, "PermitEmptyPasswords is set to 'yes'"
                return False, "PermitEmptyPasswords is 'no'"
        return False, "PermitEmptyPasswords defaults to 'no'"

    def _disable_ssh_empty_passwords(self) -> tuple[bool, str]:
        return _modify_sshd_config("PermitEmptyPasswords", "no")

    # === SSH MaxAuthTries ===
    def _check_ssh_max_auth(self) -> tuple[bool, str]:
        content = _read_file("/etc/ssh/sshd_config")
        if content is None:
            return False, "Cannot read sshd_config"
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("MaxAuthTries") and not stripped.startswith("#"):
                try:
                    val = int(stripped.split(None, 1)[1])
                    if val > 4:
                        return True, f"MaxAuthTries is {val} (should be ≤4)"
                    return False, f"MaxAuthTries is {val}"
                except (ValueError, IndexError):
                    pass
        return True, "MaxAuthTries not set (defaults to 6)"

    def _set_ssh_max_auth(self) -> tuple[bool, str]:
        return _modify_sshd_config("MaxAuthTries", "4")
