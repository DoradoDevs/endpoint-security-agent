"""
Sentinel Agent — Windows OS Module

Interrogates Windows security state using native APIs and safe WMI/PowerShell queries.
All operations are read-only. No system modifications.
"""

from __future__ import annotations

import platform
import subprocess
import json
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


def _run_powershell(command: str, timeout: int = 30) -> str:
    """Execute a PowerShell command safely and return output."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        get_logger().debug(f"PowerShell command failed: {e}")
        return ""


class WindowsModule(BaseOSModule):

    @property
    def platform_name(self) -> str:
        return "windows"

    def get_firewall_status(self) -> FirewallStatus:
        output = _run_powershell(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        )
        if not output:
            return FirewallStatus(enabled=False, details="Unable to query firewall status")

        try:
            profiles = json.loads(output)
            if isinstance(profiles, dict):
                profiles = [profiles]
            all_enabled = all(p.get("Enabled", False) for p in profiles)
            details_parts = [f"{p['Name']}: {'ON' if p.get('Enabled') else 'OFF'}" for p in profiles]
            return FirewallStatus(
                enabled=all_enabled,
                details=" | ".join(details_parts),
                extra={"profiles": profiles},
            )
        except (json.JSONDecodeError, KeyError):
            return FirewallStatus(enabled=False, details="Failed to parse firewall status")

    def get_encryption_status(self) -> EncryptionStatus:
        output = _run_powershell(
            "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue | "
            "Select-Object MountPoint, ProtectionStatus, EncryptionMethod | ConvertTo-Json"
        )
        if not output:
            return EncryptionStatus(enabled=False, method="", details="BitLocker status unavailable")

        try:
            data = json.loads(output)
            protected = data.get("ProtectionStatus", 0) == 1
            method = str(data.get("EncryptionMethod", "Unknown"))
            return EncryptionStatus(
                enabled=protected,
                method=method,
                details=f"C: {'Protected' if protected else 'Not Protected'} ({method})",
            )
        except (json.JSONDecodeError, KeyError):
            return EncryptionStatus(enabled=False, details="Failed to parse BitLocker status")

    def get_update_status(self) -> UpdateStatus:
        # Check Windows Update auto-update setting
        auto_output = _run_powershell(
            "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results | "
            "Select-Object LastSearchSuccessDate | ConvertTo-Json"
        )
        # Check for pending updates
        pending_output = _run_powershell(
            "$s = New-Object -ComObject Microsoft.Update.Session; "
            "$searcher = $s.CreateUpdateSearcher(); "
            "try { $result = $searcher.Search('IsInstalled=0'); $result.Updates.Count } "
            "catch { 'error' }",
            timeout=60,
        )

        pending = 0
        if pending_output and pending_output.isdigit():
            pending = int(pending_output)

        auto_enabled_output = _run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' "
            "-Name AUOptions -ErrorAction SilentlyContinue).AUOptions"
        )
        auto_enabled = auto_enabled_output in ("3", "4")  # 3=auto download, 4=auto install

        return UpdateStatus(
            auto_updates_enabled=auto_enabled,
            pending_updates=pending,
            details=f"Auto-updates: {'enabled' if auto_enabled else 'disabled'} | Pending: {pending}",
        )

    def get_secure_boot_status(self) -> SecureBootStatus:
        output = _run_powershell("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue")
        if output.lower() == "true":
            return SecureBootStatus(supported=True, enabled=True, details="Secure Boot is enabled")
        elif output.lower() == "false":
            return SecureBootStatus(supported=True, enabled=False, details="Secure Boot is disabled")
        return SecureBootStatus(supported=False, enabled=False, details="Secure Boot status unknown (BIOS mode?)")

    def get_startup_entries(self) -> list[StartupEntry]:
        entries: list[StartupEntry] = []

        # Registry Run keys
        for hive, label in [
            ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run"),
            ("HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU_Run"),
        ]:
            output = _run_powershell(
                f"Get-ItemProperty -Path '{hive}' -ErrorAction SilentlyContinue | "
                "ConvertTo-Json -Depth 2"
            )
            if output:
                try:
                    data = json.loads(output)
                    skip_keys = {"PSPath", "PSParentPath", "PSChildName", "PSProvider", "PSDrive"}
                    for key, val in data.items():
                        if key in skip_keys:
                            continue
                        entries.append(StartupEntry(
                            name=key,
                            command=str(val),
                            location=label,
                        ))
                except (json.JSONDecodeError, AttributeError):
                    pass

        # Scheduled tasks
        output = _run_powershell(
            "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | "
            "Select-Object TaskName, TaskPath, State -First 50 | ConvertTo-Json"
        )
        if output:
            try:
                tasks = json.loads(output)
                if isinstance(tasks, dict):
                    tasks = [tasks]
                for task in tasks:
                    entries.append(StartupEntry(
                        name=task.get("TaskName", ""),
                        command=task.get("TaskPath", ""),
                        location="ScheduledTask",
                    ))
            except (json.JSONDecodeError, AttributeError):
                pass

        return entries

    def get_running_services(self) -> list[ServiceInfo]:
        output = _run_powershell(
            "Get-Service | Where-Object { $_.Status -eq 'Running' } | "
            "Select-Object Name, DisplayName, Status, StartType -First 100 | ConvertTo-Json"
        )
        services: list[ServiceInfo] = []
        if not output:
            return services

        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            for svc in data:
                services.append(ServiceInfo(
                    name=svc.get("Name", ""),
                    display_name=svc.get("DisplayName", ""),
                    status=str(svc.get("Status", "")),
                    start_type=str(svc.get("StartType", "")),
                ))
        except (json.JSONDecodeError, AttributeError):
            pass

        return services

    def get_admin_users(self) -> list[str]:
        output = _run_powershell(
            "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name"
        )
        if not output:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]

    def get_password_policy(self) -> dict[str, Any]:
        output = _run_powershell("net accounts")
        policy: dict[str, Any] = {}
        if output:
            for line in output.splitlines():
                if ":" in line:
                    key, _, val = line.partition(":")
                    policy[key.strip()] = val.strip()
        return policy

    def get_os_patch_level(self) -> dict[str, Any]:
        version = platform.version()
        build = platform.win32_ver()

        hotfix_output = _run_powershell(
            "Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | "
            "Select-Object HotFixID, InstalledOn, Description -First 10 | ConvertTo-Json"
        )
        hotfixes = []
        if hotfix_output:
            try:
                data = json.loads(hotfix_output)
                if isinstance(data, dict):
                    data = [data]
                hotfixes = data
            except json.JSONDecodeError:
                pass

        return {
            "version": version,
            "build": build,
            "recent_hotfixes": hotfixes,
        }
