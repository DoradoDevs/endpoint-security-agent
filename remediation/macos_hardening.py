"""
Sentinel Agent — macOS Hardening Actions

All macOS-specific hardening actions. Vendor-aligned with Apple
security recommendations and CIS benchmarks.
"""

from __future__ import annotations

import subprocess

from remediation.hardening import HardeningAction


def _run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return False, str(e)


def get_macos_actions(config) -> list[HardeningAction]:
    """Return all macOS hardening actions."""
    engine = _MacOSHardening()
    return engine.actions()


class _MacOSHardening:
    """macOS hardening action definitions."""

    def actions(self) -> list[HardeningAction]:
        return [
            # === Original v1.0 actions ===
            HardeningAction(
                name="Enable macOS Firewall",
                description="Enable the Application Layer Firewall",
                severity="critical",
                check_fn=self._check_firewall,
                apply_fn=self._enable_firewall,
                platform="darwin",
            ),
            HardeningAction(
                name="Enable Firewall Stealth Mode",
                description="Enable stealth mode to ignore ICMP and other probes",
                severity="medium",
                check_fn=self._check_stealth,
                apply_fn=self._enable_stealth,
                platform="darwin",
            ),
            HardeningAction(
                name="Enable Automatic Updates",
                description="Enable automatic checking and downloading of macOS updates",
                severity="high",
                check_fn=self._check_auto_updates,
                apply_fn=self._enable_auto_updates,
                platform="darwin",
            ),
            # === New v2.0 actions ===
            HardeningAction(
                name="Enforce Gatekeeper",
                description="Ensure Gatekeeper is enabled to prevent unsigned apps from running",
                severity="high",
                check_fn=self._check_gatekeeper,
                apply_fn=self._enable_gatekeeper,
                platform="darwin",
            ),
            HardeningAction(
                name="Enforce FileVault Full-Disk Encryption",
                description="Enable FileVault 2 full-disk encryption",
                severity="high",
                check_fn=self._check_filevault,
                apply_fn=self._enable_filevault,
                platform="darwin",
            ),
            HardeningAction(
                name="Set Screen Lock Timeout",
                description="Require password within 5 seconds of screen saver/sleep",
                severity="medium",
                check_fn=self._check_screen_lock,
                apply_fn=self._set_screen_lock,
                platform="darwin",
            ),
            HardeningAction(
                name="Disable Remote Login (SSH)",
                description="Disable SSH server to prevent remote access unless needed",
                severity="medium",
                check_fn=self._check_remote_login,
                apply_fn=self._disable_remote_login,
                rollback_fn=self._enable_remote_login,
                platform="darwin",
            ),
            HardeningAction(
                name="Disable Bluetooth Sharing",
                description="Disable Bluetooth sharing to prevent data exfiltration",
                severity="low",
                check_fn=self._check_bluetooth_sharing,
                apply_fn=self._disable_bluetooth_sharing,
                platform="darwin",
            ),
            HardeningAction(
                name="Restrict AirDrop to Contacts Only",
                description="Limit AirDrop to contacts to prevent unauthorized file receipt",
                severity="low",
                check_fn=self._check_airdrop,
                apply_fn=self._restrict_airdrop,
                platform="darwin",
            ),
        ]

    # === Firewall ===
    def _check_firewall(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"
        ])
        if success and "disabled" in output.lower():
            return True, "Application Firewall is disabled"
        return False, "Firewall is enabled"

    def _enable_firewall(self) -> tuple[bool, str]:
        return _run_cmd([
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"
        ])

    # === Stealth Mode ===
    def _check_stealth(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"
        ])
        if success and "disabled" in output.lower():
            return True, "Stealth mode is disabled"
        return False, "Stealth mode is enabled"

    def _enable_stealth(self) -> tuple[bool, str]:
        return _run_cmd([
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"
        ])

    # === Auto Updates ===
    def _check_auto_updates(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled"
        ])
        if success and output.strip() != "1":
            return True, "Automatic update checking is disabled"
        return False, "Automatic updates configured"

    def _enable_auto_updates(self) -> tuple[bool, str]:
        s1 = _run_cmd([
            "defaults", "write", "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled", "-bool", "true"
        ])
        s2 = _run_cmd([
            "defaults", "write", "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticDownload", "-bool", "true"
        ])
        return s1[0] and s2[0], "Enabled automatic check and download"

    # === Gatekeeper ===
    def _check_gatekeeper(self) -> tuple[bool, str]:
        success, output = _run_cmd(["spctl", "--status"])
        if success and "disabled" in output.lower():
            return True, "Gatekeeper is disabled"
        return False, "Gatekeeper is enabled"

    def _enable_gatekeeper(self) -> tuple[bool, str]:
        return _run_cmd(["spctl", "--master-enable"])

    # === FileVault ===
    def _check_filevault(self) -> tuple[bool, str]:
        success, output = _run_cmd(["fdesetup", "status"])
        if success and "off" in output.lower():
            return True, "FileVault is not enabled"
        return False, "FileVault is enabled"

    def _enable_filevault(self) -> tuple[bool, str]:
        # FileVault requires user interaction for recovery key
        # We trigger the enablement process
        success, output = _run_cmd(["fdesetup", "enable", "-defer", "/tmp/sentinel_fv_key.plist"])
        if success:
            return True, "FileVault enablement deferred — will activate at next logout"
        return False, f"FileVault enablement failed: {output}. May require manual setup in System Settings."

    # === Screen Lock ===
    def _check_screen_lock(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "defaults", "read", "com.apple.screensaver", "askForPasswordDelay"
        ])
        if success:
            try:
                delay = int(output.strip())
                if delay > 5:
                    return True, f"Screen lock delay is {delay} seconds (should be ≤5)"
            except ValueError:
                pass
        else:
            # If not set, check if password is required at all
            s2, o2 = _run_cmd([
                "defaults", "read", "com.apple.screensaver", "askForPassword"
            ])
            if s2 and o2.strip() != "1":
                return True, "Screen lock password not required"
        return False, "Screen lock is properly configured"

    def _set_screen_lock(self) -> tuple[bool, str]:
        s1 = _run_cmd([
            "defaults", "write", "com.apple.screensaver", "askForPassword", "-int", "1"
        ])
        s2 = _run_cmd([
            "defaults", "write", "com.apple.screensaver", "askForPasswordDelay", "-int", "5"
        ])
        return s1[0] and s2[0], "Screen lock set to require password within 5 seconds"

    # === Remote Login ===
    def _check_remote_login(self) -> tuple[bool, str]:
        success, output = _run_cmd(["systemsetup", "-getremotelogin"])
        if success and "on" in output.lower():
            return True, "Remote Login (SSH) is enabled"
        return False, "Remote Login is disabled"

    def _disable_remote_login(self) -> tuple[bool, str]:
        return _run_cmd(["systemsetup", "-setremotelogin", "off"])

    def _enable_remote_login(self) -> tuple[bool, str]:
        return _run_cmd(["systemsetup", "-setremotelogin", "on"])

    # === Bluetooth Sharing ===
    def _check_bluetooth_sharing(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "defaults", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"
        ])
        if success and output.strip() == "1":
            return True, "Bluetooth sharing is enabled"
        return False, "Bluetooth sharing is disabled"

    def _disable_bluetooth_sharing(self) -> tuple[bool, str]:
        return _run_cmd([
            "defaults", "write", "com.apple.Bluetooth", "PrefKeyServicesEnabled", "-bool", "false"
        ])

    # === AirDrop ===
    def _check_airdrop(self) -> tuple[bool, str]:
        success, output = _run_cmd([
            "defaults", "read", "com.apple.NetworkBrowser", "DisableAirDrop"
        ])
        if success and output.strip() == "1":
            return False, "AirDrop is disabled"
        # Check if set to contacts only
        success2, output2 = _run_cmd([
            "defaults", "read", "com.apple.sharingd", "DiscoverableMode"
        ])
        if success2 and output2.strip() == "Contacts Only":
            return False, "AirDrop restricted to contacts only"
        return True, "AirDrop is not restricted"

    def _restrict_airdrop(self) -> tuple[bool, str]:
        return _run_cmd([
            "defaults", "write", "com.apple.sharingd", "DiscoverableMode", "-string",
            "Contacts Only"
        ])
