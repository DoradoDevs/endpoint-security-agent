"""
Sentinel Agent — Windows Hardening Actions

All Windows-specific hardening actions. Each action follows the
check_fn / apply_fn / rollback_fn pattern.

Vendor-aligned: Microsoft security baselines and CIS benchmarks.
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


def _ps(command: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a PowerShell command."""
    return _run_cmd(["powershell", "-NoProfile", "-Command", command], timeout)


def get_windows_actions(config) -> list[HardeningAction]:
    """Return all Windows hardening actions."""
    engine = _WindowsHardening()
    return engine.actions()


class _WindowsHardening:
    """Windows hardening action definitions."""

    def actions(self) -> list[HardeningAction]:
        return [
            # === Original v1.0 actions ===
            HardeningAction(
                name="Enable Windows Firewall",
                description="Enable Windows Firewall for all profiles (Domain, Private, Public)",
                severity="critical",
                check_fn=self._check_firewall,
                apply_fn=self._enable_firewall,
                platform="windows",
            ),
            HardeningAction(
                name="Enable Automatic Updates",
                description="Configure Windows Update for automatic downloads and installation",
                severity="high",
                check_fn=self._check_auto_updates,
                apply_fn=self._enable_auto_updates,
                platform="windows",
            ),
            HardeningAction(
                name="Disable SMBv1",
                description="Disable legacy SMBv1 protocol (vulnerable to EternalBlue and similar)",
                severity="high",
                check_fn=self._check_smbv1,
                apply_fn=self._disable_smbv1,
                platform="windows",
            ),
            # === New v2.0 actions ===
            HardeningAction(
                name="Enable Windows Defender Real-Time Protection",
                description="Ensure Defender real-time monitoring is active for malware detection",
                severity="critical",
                check_fn=self._check_defender_realtime,
                apply_fn=self._enable_defender_realtime,
                platform="windows",
            ),
            HardeningAction(
                name="Enable Controlled Folder Access",
                description="Enable ransomware protection via Controlled Folder Access",
                severity="high",
                check_fn=self._check_controlled_folder,
                apply_fn=self._enable_controlled_folder,
                platform="windows",
            ),
            HardeningAction(
                name="Enforce Maximum UAC Level",
                description="Set UAC to always notify on all elevation requests",
                severity="high",
                check_fn=self._check_uac_max,
                apply_fn=self._enforce_uac_max,
                platform="windows",
            ),
            HardeningAction(
                name="Disable Remote Desktop",
                description="Disable RDP to reduce remote attack surface",
                severity="medium",
                check_fn=self._check_rdp_enabled,
                apply_fn=self._disable_rdp,
                rollback_fn=self._enable_rdp,
                platform="windows",
            ),
            HardeningAction(
                name="Enable Audit Logging",
                description="Enable comprehensive security audit logging for forensics",
                severity="medium",
                check_fn=self._check_audit_logging,
                apply_fn=self._enable_audit_logging,
                platform="windows",
            ),
            HardeningAction(
                name="Disable Guest Account",
                description="Ensure the Guest account is disabled to prevent unauthorized access",
                severity="medium",
                check_fn=self._check_guest_account,
                apply_fn=self._disable_guest_account,
                platform="windows",
            ),
            HardeningAction(
                name="Enforce PowerShell Script Signing",
                description="Set PowerShell execution policy to require signed scripts",
                severity="medium",
                check_fn=self._check_ps_execution_policy,
                apply_fn=self._enforce_ps_execution_policy,
                platform="windows",
            ),
            HardeningAction(
                name="Disable Autorun/Autoplay",
                description="Disable autorun for all drives to prevent USB-based attacks",
                severity="medium",
                check_fn=self._check_autorun,
                apply_fn=self._disable_autorun,
                platform="windows",
            ),
        ]

    # === Firewall ===
    def _check_firewall(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count"
        )
        if success and output.strip() != "0":
            return True, f"{output.strip()} firewall profile(s) disabled"
        return False, "All firewall profiles enabled"

    def _enable_firewall(self) -> tuple[bool, str]:
        return _ps("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")

    # === Auto Updates ===
    def _check_auto_updates(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\WindowsUpdate\\Auto Update' -Name AUOptions -ErrorAction SilentlyContinue).AUOptions"
        )
        if success and output.strip() not in ("3", "4"):
            return True, "Automatic updates not fully configured"
        return False, "Automatic updates configured"

    def _enable_auto_updates(self) -> tuple[bool, str]:
        return _ps(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\WindowsUpdate\\Auto Update' -Name AUOptions -Value 4"
        )

    # === SMBv1 ===
    def _check_smbv1(self) -> tuple[bool, str]:
        success, output = _ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
        if success and output.strip().lower() == "true":
            return True, "SMBv1 is enabled"
        return False, "SMBv1 is disabled"

    def _disable_smbv1(self) -> tuple[bool, str]:
        return _ps("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")

    # === Windows Defender ===
    def _check_defender_realtime(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-MpPreference).DisableRealtimeMonitoring"
        )
        if success and output.strip().lower() == "true":
            return True, "Windows Defender real-time protection is disabled"
        return False, "Real-time protection is enabled"

    def _enable_defender_realtime(self) -> tuple[bool, str]:
        return _ps("Set-MpPreference -DisableRealtimeMonitoring $false")

    # === Controlled Folder Access ===
    def _check_controlled_folder(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-MpPreference).EnableControlledFolderAccess"
        )
        if success and output.strip() != "1":
            return True, "Controlled Folder Access is not enabled"
        return False, "Controlled Folder Access is enabled"

    def _enable_controlled_folder(self) -> tuple[bool, str]:
        return _ps("Set-MpPreference -EnableControlledFolderAccess Enabled")

    # === UAC ===
    def _check_uac_max(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\System' -Name ConsentPromptBehaviorAdmin "
            "-ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"
        )
        if success:
            try:
                level = int(output.strip())
                if level < 2:
                    return True, f"UAC level is {level} (should be 2 or higher)"
            except ValueError:
                pass
        return False, "UAC is at recommended level"

    def _enforce_uac_max(self) -> tuple[bool, str]:
        return _ps(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2"
        )

    # === Remote Desktop ===
    def _check_rdp_enabled(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control"
            "\\Terminal Server' -Name fDenyTSConnections "
            "-ErrorAction SilentlyContinue).fDenyTSConnections"
        )
        if success and output.strip() == "0":
            return True, "Remote Desktop is enabled"
        return False, "Remote Desktop is disabled"

    def _disable_rdp(self) -> tuple[bool, str]:
        return _ps(
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control"
            "\\Terminal Server' -Name fDenyTSConnections -Value 1; "
            "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
        )

    def _enable_rdp(self) -> tuple[bool, str]:
        return _ps(
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control"
            "\\Terminal Server' -Name fDenyTSConnections -Value 0; "
            "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
        )

    # === Audit Logging ===
    def _check_audit_logging(self) -> tuple[bool, str]:
        success, output = _ps(
            "auditpol /get /category:'Logon/Logoff' 2>$null | Select-String 'No Auditing'"
        )
        if success and output.strip():
            return True, "Some audit categories have no auditing configured"
        return False, "Audit logging is configured"

    def _enable_audit_logging(self) -> tuple[bool, str]:
        commands = [
            "auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable",
            "auditpol /set /category:'Account Logon' /success:enable /failure:enable",
            "auditpol /set /category:'Account Management' /success:enable /failure:enable",
            "auditpol /set /category:'Privilege Use' /success:enable /failure:enable",
        ]
        all_ok = True
        for cmd in commands:
            s, _ = _ps(cmd)
            if not s:
                all_ok = False
        return all_ok, "Security audit logging enabled for key categories"

    # === Guest Account ===
    def _check_guest_account(self) -> tuple[bool, str]:
        success, output = _ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
        if success and output.strip().lower() == "true":
            return True, "Guest account is enabled"
        return False, "Guest account is disabled"

    def _disable_guest_account(self) -> tuple[bool, str]:
        return _ps("Disable-LocalUser -Name 'Guest'")

    # === PowerShell Execution Policy ===
    def _check_ps_execution_policy(self) -> tuple[bool, str]:
        success, output = _ps("Get-ExecutionPolicy -Scope LocalMachine")
        if success and output.strip().lower() in ("unrestricted", "bypass"):
            return True, f"PowerShell execution policy is '{output.strip()}'"
        return False, f"Execution policy is '{output.strip() if success else 'unknown'}'"

    def _enforce_ps_execution_policy(self) -> tuple[bool, str]:
        return _ps("Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force")

    # === Autorun ===
    def _check_autorun(self) -> tuple[bool, str]:
        success, output = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\Explorer' -Name NoDriveTypeAutoRun "
            "-ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
        )
        if success and output.strip() == "255":
            return False, "Autorun is disabled for all drives"
        return True, "Autorun is not fully disabled"

    def _disable_autorun(self) -> tuple[bool, str]:
        return _ps(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            "\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Force"
        )
