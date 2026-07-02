"""Tests for scanners.config_scanner — Configuration Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig
from scanners.config_scanner import ConfigScanner


@pytest.fixture
def scanner():
    return ConfigScanner(AgentConfig())


class TestConfigScanner:

    def test_properties(self, scanner):
        assert scanner.name == "Configuration Scanner"
        assert "all" in scanner.supported_platforms

    @patch("scanners.config_scanner.load_os_module")
    @patch("scanners.config_scanner.platform.system", return_value="Windows")
    def test_encryption_disabled_critical(self, _plat, mock_loader, scanner):
        from os_modules.base import (
            EncryptionStatus, SecureBootStatus, UpdateStatus, FirewallStatus,
        )
        mock_module = MagicMock()
        mock_module.get_encryption_status.return_value = EncryptionStatus(
            enabled=False, method="None", details="No encryption",
        )
        mock_module.get_secure_boot_status.return_value = SecureBootStatus(
            supported=True, enabled=True,
        )
        mock_module.get_admin_users.return_value = ["Administrator"]
        mock_module.get_password_policy.return_value = {"Minimum password length": "8"}
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=True, pending_updates=0,
        )
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        # Encryption disabled is HIGH severity, not critical
        high = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high) >= 1
        assert any("encrypt" in f.title.lower() for f in high)

    @patch("scanners.config_scanner.load_os_module")
    @patch("scanners.config_scanner.platform.system", return_value="Windows")
    def test_fully_secured_system(self, _plat, mock_loader, mock_os_module):
        mock_loader.return_value = mock_os_module
        scanner = ConfigScanner(AgentConfig())

        findings = scanner.scan()
        critical_high = [f for f in findings
                         if f.severity.value in ("critical", "high")]
        assert len(critical_high) == 0

    @patch("scanners.config_scanner.load_os_module")
    @patch("scanners.config_scanner.platform.system", return_value="Windows")
    def test_many_admin_users_warning(self, _plat, mock_loader, scanner):
        from os_modules.base import (
            EncryptionStatus, SecureBootStatus, UpdateStatus,
        )
        mock_module = MagicMock()
        mock_module.get_encryption_status.return_value = EncryptionStatus(enabled=True)
        mock_module.get_secure_boot_status.return_value = SecureBootStatus(
            supported=True, enabled=True,
        )
        mock_module.get_admin_users.return_value = [
            "Admin1", "Admin2", "Admin3", "Admin4", "Admin5",
        ]
        mock_module.get_password_policy.return_value = {"Minimum password length": "8"}
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=True, pending_updates=0,
        )
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        admin_findings = [f for f in findings if "admin" in f.title.lower()]
        assert len(admin_findings) >= 1

    @patch("scanners.config_scanner.load_os_module")
    @patch("scanners.config_scanner.platform.system", return_value="Linux")
    def test_ssh_root_login_critical(self, _plat, mock_loader, scanner):
        from os_modules.base import (
            EncryptionStatus, SecureBootStatus, UpdateStatus,
        )
        scanner.config.scan.server_mode = True

        mock_module = MagicMock()
        mock_module.get_encryption_status.return_value = EncryptionStatus(enabled=True)
        mock_module.get_secure_boot_status.return_value = SecureBootStatus(
            supported=True, enabled=True,
        )
        mock_module.get_admin_users.return_value = ["root"]
        mock_module.get_password_policy.return_value = {"PASS_MAX_DAYS": "99999"}
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=True, pending_updates=0,
        )
        mock_module.get_ssh_config.return_value = {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "no",
        }
        mock_module.get_open_ports.return_value = [
            {"address": "0.0.0.0:22", "port": 22},
            {"address": "0.0.0.0:80", "port": 80},
            {"address": "0.0.0.0:443", "port": 443},
        ]
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        critical = [f for f in findings if f.severity.value == "critical"]
        assert any("root" in f.title.lower() or "ssh" in f.title.lower()
                    for f in critical)
