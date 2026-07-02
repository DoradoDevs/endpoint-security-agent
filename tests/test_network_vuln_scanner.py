"""Tests for the Network Vulnerability Scanner."""

from unittest.mock import patch, MagicMock
import socket

from core.config import AgentConfig, Severity
from scanners.network_vuln_scanner import (
    NetworkVulnScanner,
    COMMON_PORTS,
    HIGH_RISK_PORTS,
    VULNERABLE_BANNERS,
)
from scanners.ssl_analyzer import SSLAnalyzer, SSLResult, WEAK_CIPHERS, DEPRECATED_PROTOCOLS


class TestNetworkVulnScanner:
    """Tests for NetworkVulnScanner."""

    def _make_config(self, targets: list[str] | None = None) -> AgentConfig:
        config = AgentConfig()
        config.scan.enable_network_vuln_scan = True
        config.scan.network_scan_targets = targets or []
        return config

    def test_properties(self):
        config = self._make_config()
        scanner = NetworkVulnScanner(config)
        assert scanner.name == "NetworkVulnScanner"
        assert "SSL" in scanner.description or "port" in scanner.description.lower()

    def test_no_targets_returns_info(self):
        """Should return INFO finding when no targets configured."""
        config = self._make_config(targets=[])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "No network scan targets" in findings[0].title

    @patch("scanners.network_vuln_scanner.socket.gethostbyname")
    def test_dns_resolution_failure(self, mock_resolve):
        """Should report DNS resolution failure."""
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")
        config = self._make_config(targets=["nonexistent.invalid"])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()
        assert any("DNS resolution failed" in f.title for f in findings)

    @patch("scanners.network_vuln_scanner.socket.create_connection")
    @patch("scanners.network_vuln_scanner.socket.gethostbyname")
    def test_no_open_ports(self, mock_resolve, mock_conn):
        """Should report when no ports are open."""
        mock_resolve.return_value = "10.0.0.1"
        mock_conn.side_effect = ConnectionRefusedError()
        config = self._make_config(targets=["safe.example.com"])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()
        assert any("No open ports" in f.title for f in findings)

    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._check_dns")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._analyze_ssl")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._grab_banner")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._tcp_scan")
    @patch("scanners.network_vuln_scanner.socket.gethostbyname")
    def test_high_risk_port_detected(
        self, mock_resolve, mock_tcp, mock_banner, mock_ssl, mock_dns
    ):
        """Should flag high-risk open ports."""
        mock_resolve.return_value = "10.0.0.1"
        mock_tcp.return_value = [22, 3389, 6379]
        mock_banner.return_value = ""
        mock_ssl.return_value = []
        mock_dns.return_value = []

        config = self._make_config(targets=["target.example.com"])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()

        high_risk = [f for f in findings if "High-risk port" in f.title]
        assert len(high_risk) == 2  # 3389 and 6379
        ports_found = [f.evidence.get("port") for f in high_risk]
        assert 3389 in ports_found
        assert 6379 in ports_found

    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._check_dns")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._analyze_ssl")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._grab_banner")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._tcp_scan")
    @patch("scanners.network_vuln_scanner.socket.gethostbyname")
    def test_vulnerable_banner_detected(
        self, mock_resolve, mock_tcp, mock_banner, mock_ssl, mock_dns
    ):
        """Should flag vulnerable service versions in banners."""
        mock_resolve.return_value = "10.0.0.1"
        mock_tcp.return_value = [22]
        mock_banner.return_value = "SSH-2.0-OpenSSH_7.4"
        mock_ssl.return_value = []
        mock_dns.return_value = []

        config = self._make_config(targets=["target.example.com"])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()

        vuln = [f for f in findings if "vulnerable" in f.title.lower()]
        assert len(vuln) >= 1
        assert vuln[0].severity == Severity.HIGH

    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._check_dns")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._analyze_ssl")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._grab_banner")
    @patch("scanners.network_vuln_scanner.NetworkVulnScanner._tcp_scan")
    @patch("scanners.network_vuln_scanner.socket.gethostbyname")
    def test_server_header_exposed(
        self, mock_resolve, mock_tcp, mock_banner, mock_ssl, mock_dns
    ):
        """Should flag exposed server version headers."""
        mock_resolve.return_value = "10.0.0.1"
        mock_tcp.return_value = [80]
        mock_banner.return_value = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        mock_ssl.return_value = []
        mock_dns.return_value = []

        config = self._make_config(targets=["web.example.com"])
        scanner = NetworkVulnScanner(config)
        findings = scanner.scan()

        server_exposed = [f for f in findings if "Server version exposed" in f.title]
        assert len(server_exposed) >= 1

    def test_common_ports_list(self):
        """Common ports list should include standard ports."""
        assert 22 in COMMON_PORTS
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 3389 in COMMON_PORTS

    def test_high_risk_ports_have_descriptions(self):
        """All high-risk ports should have descriptions."""
        for port, desc in HIGH_RISK_PORTS.items():
            assert isinstance(desc, str)
            assert len(desc) > 5

    def test_vulnerable_banners_have_descriptions(self):
        """All vulnerable banner patterns should have descriptions."""
        for pattern, desc in VULNERABLE_BANNERS:
            assert isinstance(pattern, str)
            assert isinstance(desc, str)
            assert len(desc) > 5


class TestSSLAnalyzer:
    """Tests for SSLAnalyzer."""

    def test_ssl_result_to_dict(self):
        """SSLResult should serialize properly."""
        result = SSLResult(
            host="example.com",
            port=443,
            is_expired=True,
            is_self_signed=False,
            cipher_name="AES256-SHA256",
            cipher_bits=256,
            days_until_expiry=-10,
        )
        d = result.to_dict()
        assert d["host"] == "example.com"
        assert d["is_expired"] is True
        assert d["cipher_bits"] == 256

    def test_weak_ciphers_defined(self):
        """Weak cipher list should include known weak algorithms."""
        assert "RC4" in WEAK_CIPHERS
        assert "DES" in WEAK_CIPHERS
        assert "NULL" in WEAK_CIPHERS

    def test_deprecated_protocols_defined(self):
        """Deprecated protocol list should include old TLS versions."""
        assert "SSLv3" in DEPRECATED_PROTOCOLS
        assert "TLSv1" in DEPRECATED_PROTOCOLS
        assert "TLSv1.1" in DEPRECATED_PROTOCOLS

    @patch("scanners.ssl_analyzer.socket.create_connection")
    def test_connection_timeout(self, mock_conn):
        """Should handle connection timeouts gracefully."""
        mock_conn.side_effect = socket.timeout("timed out")
        analyzer = SSLAnalyzer()
        result = analyzer.analyze("unreachable.example.com", 443)
        assert any("timed out" in issue for issue in result.issues)

    @patch("scanners.ssl_analyzer.socket.create_connection")
    def test_connection_refused(self, mock_conn):
        """Should handle connection refused gracefully."""
        mock_conn.side_effect = ConnectionRefusedError()
        analyzer = SSLAnalyzer()
        result = analyzer.analyze("nossl.example.com", 443)
        assert any("refused" in issue.lower() for issue in result.issues)

    def test_check_cipher_weak(self):
        """Should detect weak ciphers."""
        analyzer = SSLAnalyzer()
        result = SSLResult(host="test", port=443, cipher_name="RC4-SHA", cipher_bits=128)
        analyzer._check_cipher(result)
        assert result.weak_cipher is True

    def test_check_cipher_weak_bits(self):
        """Should flag low bit strength."""
        analyzer = SSLAnalyzer()
        result = SSLResult(host="test", port=443, cipher_name="SOME-CIPHER", cipher_bits=56)
        analyzer._check_cipher(result)
        assert result.weak_cipher is True

    def test_check_cipher_strong(self):
        """Should not flag strong ciphers."""
        analyzer = SSLAnalyzer()
        result = SSLResult(host="test", port=443, cipher_name="ECDHE-RSA-AES256-GCM-SHA384", cipher_bits=256)
        analyzer._check_cipher(result)
        assert result.weak_cipher is False

    def test_check_protocol_deprecated(self):
        """Should flag deprecated protocols."""
        analyzer = SSLAnalyzer()
        result = SSLResult(host="test", port=443, protocol_version="TLSv1")
        analyzer._check_protocol(result)
        assert any("Deprecated" in issue for issue in result.issues)

    def test_check_protocol_current(self):
        """Should not flag TLS 1.2+."""
        analyzer = SSLAnalyzer()
        result = SSLResult(host="test", port=443, protocol_version="TLSv1.2")
        analyzer._check_protocol(result)
        assert not any("Deprecated" in issue for issue in result.issues)
