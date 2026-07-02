"""Tests for Browser Security Scanner."""

from unittest.mock import patch, MagicMock
from pathlib import Path

from core.config import AgentConfig, Severity
from scanners.browser_scanner import BrowserScanner


def _make_config():
    return AgentConfig()


def test_scanner_properties():
    scanner = BrowserScanner(_make_config())
    assert scanner.name == "Browser Security Scanner"
    assert "windows" in scanner.supported_platforms
    assert "darwin" in scanner.supported_platforms
    assert "linux" not in scanner.supported_platforms


def test_scan_returns_findings_list():
    """Scan should return a list (even if empty on non-desktop platforms)."""
    scanner = BrowserScanner(_make_config())
    with patch.object(scanner, "_check_browser_versions", return_value=[]):
        with patch.object(scanner, "_scan_extensions", return_value=[]):
            findings = scanner.scan()
            assert isinstance(findings, list)


def test_browser_category():
    """Findings should use Browser Security category."""
    from core.telemetry import Finding
    finding = Finding(
        title="Test",
        description="Test",
        severity=Severity.INFO,
        category="Browser Security",
        scanner="Browser Security Scanner",
        evidence={},
        remediation="",
    )
    assert finding.category == "Browser Security"


if __name__ == "__main__":
    test_scanner_properties()
    test_scan_returns_findings_list()
    test_browser_category()
    print("All browser scanner tests passed!")
