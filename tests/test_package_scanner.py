"""Tests for scanners.package_scanner — Package Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig
from scanners.package_scanner import PackageScanner


@pytest.fixture
def scanner():
    return PackageScanner(AgentConfig())


class TestPackageScanner:

    def test_properties(self, scanner):
        assert scanner.name == "Package Scanner"
        assert "all" in scanner.supported_platforms

    @patch("scanners.package_scanner.load_os_module")
    @patch("scanners.package_scanner.platform.system", return_value="Windows")
    def test_windows_no_updates_pending(self, _plat, mock_loader, scanner):
        from os_modules.base import UpdateStatus
        mock_module = MagicMock()
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=True, pending_updates=0,
            last_check="2024-01-01", details="Up to date",
        )
        mock_module.get_os_patch_level.return_value = {"version": "10.0.22631"}
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) == 0

    @patch("scanners.package_scanner.load_os_module")
    @patch("scanners.package_scanner.platform.system", return_value="Windows")
    def test_windows_many_updates_pending(self, _plat, mock_loader, scanner):
        from os_modules.base import UpdateStatus
        mock_module = MagicMock()
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=False, pending_updates=15,
            last_check="2024-01-01", details="15 updates pending",
        )
        mock_module.get_os_patch_level.return_value = {"version": "10.0.22631"}
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) >= 1

    @patch("scanners.package_scanner.load_os_module")
    @patch("scanners.package_scanner.subprocess.run")
    @patch("scanners.package_scanner.platform.system", return_value="Linux")
    def test_linux_apt_upgradable(self, _plat, mock_run, mock_loader, scanner):
        from os_modules.base import UpdateStatus
        mock_module = MagicMock()
        mock_module.get_update_status.return_value = UpdateStatus(
            auto_updates_enabled=True, pending_updates=5,
        )
        mock_module.get_os_patch_level.return_value = {"version": "22.04", "kernel": "6.5.0"}
        mock_loader.return_value = mock_module

        # apt list --upgradable
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Listing... Done\nlibssl3/jammy-security 3.0.13-0ubuntu0.22.04.1 amd64 [upgradable]\n"
                   "openssl/jammy-security 3.0.13-0ubuntu0.22.04.1 amd64 [upgradable]\n"
        )

        findings = scanner.scan()
        assert any("update" in f.title.lower() or "upgrade" in f.title.lower()
                    for f in findings)
