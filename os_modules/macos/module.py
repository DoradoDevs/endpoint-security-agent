"""
Sentinel Agent — macOS OS Module

Interrogates macOS security state using native tools (system_profiler, defaults,
csrutil, fdesetup, etc.). All operations are read-only.
"""

from __future__ import annotations

import plistlib
import subprocess
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


def _run_cmd_bytes(args: list[str], timeout: int = 30) -> bytes:
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return b""


class MacOSModule(BaseOSModule):

    @property
    def platform_name(self) -> str:
        return "darwin"

    def get_firewall_status(self) -> FirewallStatus:
        # Application Firewall
        output = _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        enabled = "enabled" in output.lower() if output else False

        # Stealth mode
        stealth = _run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
        stealth_on = "enabled" in stealth.lower() if stealth else False

        details = f"Application Firewall: {'ON' if enabled else 'OFF'} | Stealth: {'ON' if stealth_on else 'OFF'}"
        return FirewallStatus(
            enabled=enabled,
            details=details,
            extra={"stealth_mode": stealth_on},
        )

    def get_encryption_status(self) -> EncryptionStatus:
        output = _run_cmd(["fdesetup", "status"])
        if not output:
            return EncryptionStatus(enabled=False, details="Unable to query FileVault")

        enabled = "on" in output.lower()
        return EncryptionStatus(
            enabled=enabled,
            method="FileVault 2" if enabled else "",
            details=output,
        )

    def get_update_status(self) -> UpdateStatus:
        auto_check = _run_cmd(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
        auto_download = _run_cmd(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"])

        auto_enabled = auto_check == "1" and auto_download == "1"

        # Check for pending updates
        updates_output = _run_cmd(["softwareupdate", "--list"], timeout=60)
        pending = updates_output.count("* Label:") if updates_output else 0

        return UpdateStatus(
            auto_updates_enabled=auto_enabled,
            pending_updates=pending,
            details=f"Auto-check: {auto_check} | Auto-download: {auto_download} | Pending: {pending}",
        )

    def get_secure_boot_status(self) -> SecureBootStatus:
        # Only applicable to Apple Silicon and T2 Macs
        output = _run_cmd(["csrutil", "status"])
        sip_enabled = "enabled" in output.lower() if output else False

        return SecureBootStatus(
            supported=True,
            enabled=sip_enabled,
            details=f"SIP (System Integrity Protection): {'enabled' if sip_enabled else 'disabled'}",
        )

    def get_startup_entries(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []

        # LaunchAgents and LaunchDaemons
        import pathlib
        launch_dirs = [
            pathlib.Path("/Library/LaunchAgents"),
            pathlib.Path("/Library/LaunchDaemons"),
            pathlib.Path.home() / "Library" / "LaunchAgents",
        ]

        for launch_dir in launch_dirs:
            if not launch_dir.exists():
                continue
            for plist_file in launch_dir.glob("*.plist"):
                try:
                    data = plistlib.loads(plist_file.read_bytes())
                    program = data.get("Program", "")
                    args = data.get("ProgramArguments", [])
                    cmd = program or (" ".join(args) if args else "unknown")
                    label = data.get("Label", plist_file.stem)
                    entries.append(StartupEntry(
                        name=label,
                        command=cmd,
                        location=str(launch_dir),
                        enabled=not data.get("Disabled", False),
                    ))
                except Exception:
                    entries.append(StartupEntry(
                        name=plist_file.stem,
                        command="(unreadable plist)",
                        location=str(launch_dir),
                    ))

        # Login Items
        output = _run_cmd(["osascript", "-e",
                           'tell application "System Events" to get name of every login item'])
        if output and output != "":
            for item in output.split(", "):
                entries.append(StartupEntry(
                    name=item.strip(),
                    command="(login item)",
                    location="LoginItems",
                ))

        return entries

    def get_running_services(self) -> list[ServiceInfo]:
        output = _run_cmd(["launchctl", "list"])
        services: list[ServiceInfo] = []
        if not output:
            return services

        for line in output.splitlines()[1:]:  # Skip header
            parts = line.split("\t")
            if len(parts) >= 3:
                pid_str, status, label = parts[0], parts[1], parts[2]
                pid = int(pid_str) if pid_str.isdigit() else 0
                services.append(ServiceInfo(
                    name=label,
                    display_name=label,
                    status="running" if pid > 0 else "loaded",
                    start_type="launchd",
                    pid=pid,
                ))

        return services

    def get_admin_users(self) -> list[str]:
        output = _run_cmd(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        if not output:
            return []
        # Format: "GroupMembership: user1 user2 ..."
        if ":" in output:
            _, _, members = output.partition(":")
            return members.strip().split()
        return []

    def get_password_policy(self) -> dict[str, Any]:
        output = _run_cmd(["pwpolicy", "getaccountpolicies"])
        return {"raw_policy": output[:2000] if output else "Unable to retrieve"}

    def get_os_patch_level(self) -> dict[str, Any]:
        version = _run_cmd(["sw_vers", "-productVersion"])
        build = _run_cmd(["sw_vers", "-buildVersion"])
        return {
            "product_version": version,
            "build_version": build,
        }
