"""Tests for scanners.network_scanner — Network Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig
from scanners.network_scanner import NetworkScanner


@pytest.fixture
def scanner():
    return NetworkScanner(AgentConfig())


def _mock_connection(laddr_port, raddr_port=0, status="LISTEN", pid=1000):
    conn = MagicMock()
    conn.laddr = MagicMock()
    conn.laddr.port = laddr_port
    conn.laddr.ip = "0.0.0.0"
    conn.raddr = MagicMock() if raddr_port else None
    if raddr_port:
        conn.raddr.port = raddr_port
        conn.raddr.ip = "1.2.3.4"
    conn.status = status
    conn.pid = pid
    return conn


class TestNetworkScanner:

    def test_properties(self, scanner):
        assert scanner.name == "Network Scanner"
        assert "all" in scanner.supported_platforms

    @patch("scanners.network_scanner.load_os_module")
    @patch("scanners.network_scanner.psutil")
    def test_firewall_disabled_critical(self, mock_psutil, mock_loader, scanner):
        from os_modules.base import FirewallStatus
        mock_module = MagicMock()
        mock_module.get_firewall_status.return_value = FirewallStatus(
            enabled=False, details="Firewall off"
        )
        mock_loader.return_value = mock_module
        mock_psutil.net_connections.return_value = []

        findings = scanner.scan()
        critical = [f for f in findings if f.severity.value == "critical"]
        assert len(critical) >= 1
        assert any("firewall" in f.title.lower() for f in critical)

    @patch("scanners.network_scanner.load_os_module")
    @patch("scanners.network_scanner.psutil")
    def test_high_risk_port_detected(self, mock_psutil, mock_loader, scanner):
        from os_modules.base import FirewallStatus
        mock_module = MagicMock()
        mock_module.get_firewall_status.return_value = FirewallStatus(enabled=True)
        mock_loader.return_value = mock_module

        mock_psutil.net_connections.return_value = [
            _mock_connection(4444),  # Known high-risk port
        ]
        mock_psutil.Process.return_value.name.return_value = "nc.exe"
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception

        findings = scanner.scan()
        high_risk = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_risk) >= 1

    @patch("scanners.network_scanner.load_os_module")
    @patch("scanners.network_scanner.psutil")
    def test_clean_system_only_inventory(self, mock_psutil, mock_loader, scanner):
        from os_modules.base import FirewallStatus
        mock_module = MagicMock()
        mock_module.get_firewall_status.return_value = FirewallStatus(enabled=True)
        mock_loader.return_value = mock_module

        mock_psutil.net_connections.return_value = [
            _mock_connection(443),  # Normal HTTPS
        ]
        mock_psutil.Process.return_value.name.return_value = "httpd"
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception

        findings = scanner.scan()
        # Should not have critical/high findings for normal ports
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) == 0
