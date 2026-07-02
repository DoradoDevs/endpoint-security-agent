"""Tests for os_modules.windows — Windows OS Module."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest


class TestWindowsModule:

    @patch("os_modules.windows.module.platform.system", return_value="Windows")
    def test_platform_name(self, _plat):
        from os_modules.windows.module import WindowsModule
        mod = WindowsModule()
        assert mod.platform_name == "windows"

    @patch("os_modules.windows.module._run_powershell")
    def test_firewall_all_enabled(self, mock_ps):
        from os_modules.windows.module import WindowsModule
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": True},
            {"Name": "Public", "Enabled": True},
        ]
        mock_ps.return_value = json.dumps(profiles)

        mod = WindowsModule()
        status = mod.get_firewall_status()
        assert status.enabled is True

    @patch("os_modules.windows.module._run_powershell")
    def test_firewall_disabled(self, mock_ps):
        from os_modules.windows.module import WindowsModule
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": False},
            {"Name": "Public", "Enabled": True},
        ]
        mock_ps.return_value = json.dumps(profiles)

        mod = WindowsModule()
        status = mod.get_firewall_status()
        assert status.enabled is False

    @patch("os_modules.windows.module._run_powershell")
    def test_encryption_bitlocker_enabled(self, mock_ps):
        from os_modules.windows.module import WindowsModule
        mock_ps.return_value = json.dumps({
            "ProtectionStatus": 1,
            "VolumeStatus": "FullyEncrypted",
            "EncryptionMethod": "XtsAes256",
        })

        mod = WindowsModule()
        status = mod.get_encryption_status()
        assert status.enabled is True
        assert "bitlocker" in status.method.lower() or "aes" in status.method.lower()

    @patch("os_modules.windows.module._run_powershell")
    def test_admin_users_parsed(self, mock_ps):
        from os_modules.windows.module import WindowsModule
        mock_ps.return_value = "Administrator\nJohn\n"

        mod = WindowsModule()
        users = mod.get_admin_users()
        assert "Administrator" in users
        assert len(users) >= 1

    @patch("os_modules.windows.module._run_powershell", return_value="")
    def test_graceful_failure(self, mock_ps):
        from os_modules.windows.module import WindowsModule
        mod = WindowsModule()
        # _run_powershell catches exceptions internally and returns ""
        # Empty string should produce a safe default FirewallStatus
        status = mod.get_firewall_status()
        assert status is not None
        assert status.enabled is False
