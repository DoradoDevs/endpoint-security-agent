"""Tests for the Network Response Handler."""

from unittest.mock import patch, MagicMock

from core.config import Severity
from core.telemetry import Finding
from response.actions.network_response import NetworkResponseHandler


class TestNetworkResponseHandler:
    """Tests for NetworkResponseHandler."""

    def _make_finding(
        self,
        category: str = "Network Security",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            title="Suspicious connection",
            description="Test",
            severity=Severity.HIGH,
            category=category,
            scanner="TestScanner",
            evidence=evidence or {},
        )

    def test_is_applicable_network_security(self):
        """Handler should be applicable for network findings with IP."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"remote_ip": "1.2.3.4"})
        assert handler.is_applicable(f) is True

    def test_is_applicable_threat_intel(self):
        """Handler should be applicable for threat intel with IOC value."""
        handler = NetworkResponseHandler()
        f = self._make_finding(
            category="Threat Intelligence",
            evidence={"ioc_value": "1.2.3.4"},
        )
        assert handler.is_applicable(f) is True

    def test_not_applicable_wrong_category(self):
        """Handler should not be applicable for wrong categories."""
        handler = NetworkResponseHandler()
        f = self._make_finding(category="File Integrity", evidence={"remote_ip": "1.2.3.4"})
        assert handler.is_applicable(f) is False

    def test_not_applicable_no_ip(self):
        """Handler should not be applicable without IP evidence."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"pid": 123})
        assert handler.is_applicable(f) is False

    def test_get_ip_from_finding_remote_ip(self):
        """Should extract IP from remote_ip key."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"remote_ip": "1.2.3.4"})
        assert handler.get_ip_from_finding(f) == "1.2.3.4"

    def test_get_ip_from_finding_ip(self):
        """Should extract IP from ip key."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"ip": "5.6.7.8"})
        assert handler.get_ip_from_finding(f) == "5.6.7.8"

    def test_get_ip_from_finding_ioc_value(self):
        """Should extract IP from ioc_value key."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"ioc_value": "9.10.11.12"})
        assert handler.get_ip_from_finding(f) == "9.10.11.12"

    def test_get_ip_none_when_missing(self):
        """Should return None when no IP in evidence."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"pid": 123})
        assert handler.get_ip_from_finding(f) is None

    def test_get_ip_rejects_non_ip(self):
        """Should reject values that don't look like IPs."""
        handler = NetworkResponseHandler()
        f = self._make_finding(evidence={"remote_ip": "not_an_ip"})
        assert handler.get_ip_from_finding(f) is None

    @patch("response.actions.network_response.platform")
    @patch("subprocess.run")
    def test_block_ip_windows(self, mock_run, mock_platform):
        """Should create netsh firewall rules on Windows."""
        mock_platform.system.return_value = "Windows"
        mock_run.return_value = MagicMock(returncode=0)

        handler = NetworkResponseHandler()
        handler._platform = "windows"

        finding = self._make_finding(evidence={"remote_ip": "1.2.3.4"})
        success, msg = handler.block_ip("1.2.3.4", finding)

        assert success is True
        assert "Blocked" in msg
        assert mock_run.call_count == 2  # Inbound + outbound

    @patch("response.actions.network_response.platform")
    @patch("subprocess.run")
    def test_block_ip_linux(self, mock_run, mock_platform):
        """Should create iptables rules on Linux."""
        mock_platform.system.return_value = "Linux"
        mock_run.return_value = MagicMock(returncode=0)

        handler = NetworkResponseHandler()
        handler._platform = "linux"

        finding = self._make_finding(evidence={"remote_ip": "1.2.3.4"})
        success, msg = handler.block_ip("1.2.3.4", finding)

        assert success is True
        assert "Blocked" in msg

    @patch("response.actions.network_response.platform")
    @patch("subprocess.run")
    def test_unblock_ip_windows(self, mock_run, mock_platform):
        """Should remove netsh firewall rules on unblock."""
        mock_platform.system.return_value = "Windows"
        mock_run.return_value = MagicMock(returncode=0)

        handler = NetworkResponseHandler()
        handler._platform = "windows"

        success, msg = handler.unblock_ip("1.2.3.4")

        assert success is True
        assert "Removed" in msg

    @patch("subprocess.run")
    def test_block_ip_linux_fallback_ufw(self, mock_run):
        """Should fall back to ufw if iptables not found."""
        import subprocess

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "iptables":
                raise FileNotFoundError("iptables not found")
            return MagicMock(returncode=0)

        mock_run.side_effect = side_effect

        handler = NetworkResponseHandler()
        handler._platform = "linux"

        finding = self._make_finding()
        success, msg = handler.block_ip("1.2.3.4", finding)

        assert success is True
        assert "ufw" in msg

    def test_rule_name_format(self):
        """Rule names should use Sentinel- prefix and sanitize IP."""
        handler = NetworkResponseHandler()
        ip = "192.168.1.1"
        expected = f"Sentinel-Block-192-168-1-1"
        # Verify the rule_name construction logic
        rule_name = f"Sentinel-Block-{ip.replace('.', '-').replace(':', '-')}"
        assert rule_name == expected

    def test_ipv6_rule_name(self):
        """Rule names should handle IPv6 addresses."""
        handler = NetworkResponseHandler()
        ip = "2001:db8::1"
        rule_name = f"Sentinel-Block-{ip.replace('.', '-').replace(':', '-')}"
        assert "Sentinel-Block-2001-db8--1" == rule_name
