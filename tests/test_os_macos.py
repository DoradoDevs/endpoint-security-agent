"""Tests for os_modules.macos — macOS OS Module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


class TestMacOSModule:

    def test_platform_name(self):
        from os_modules.macos.module import MacOSModule
        mod = MacOSModule()
        assert mod.platform_name == "darwin"

    @patch("os_modules.macos.module._run_cmd")
    def test_firewall_enabled(self, mock_cmd):
        from os_modules.macos.module import MacOSModule
        mock_cmd.return_value = "Firewall is enabled. (State = 1)"

        mod = MacOSModule()
        status = mod.get_firewall_status()
        assert status.enabled is True

    @patch("os_modules.macos.module._run_cmd")
    def test_firewall_disabled(self, mock_cmd):
        from os_modules.macos.module import MacOSModule
        mock_cmd.return_value = "Firewall is disabled. (State = 0)"

        mod = MacOSModule()
        status = mod.get_firewall_status()
        assert status.enabled is False

    @patch("os_modules.macos.module._run_cmd")
    def test_filevault_enabled(self, mock_cmd):
        from os_modules.macos.module import MacOSModule
        mock_cmd.return_value = "FileVault is On."

        mod = MacOSModule()
        status = mod.get_encryption_status()
        assert status.enabled is True
        assert "filevault" in status.method.lower()

    @patch("os_modules.macos.module._run_cmd")
    def test_sip_enabled(self, mock_cmd):
        from os_modules.macos.module import MacOSModule
        mock_cmd.return_value = "System Integrity Protection status: enabled."

        mod = MacOSModule()
        status = mod.get_secure_boot_status()
        assert status.enabled is True

    @patch("os_modules.macos.module._run_cmd")
    def test_admin_users(self, mock_cmd):
        from os_modules.macos.module import MacOSModule
        # dscl returns "GroupMembership: user1 user2 ..."
        mock_cmd.return_value = "GroupMembership: admin john"

        mod = MacOSModule()
        users = mod.get_admin_users()
        assert len(users) >= 1
        assert "admin" in users
