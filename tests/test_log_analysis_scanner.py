"""Tests for Log Analysis Scanner."""

from unittest.mock import patch

from core.config import AgentConfig, Severity
from scanners.log_analysis_scanner import LogAnalysisScanner


def _make_config():
    return AgentConfig()


def test_scanner_properties():
    scanner = LogAnalysisScanner(_make_config())
    assert scanner.name == "Log Analysis Scanner"
    assert "windows" in scanner.supported_platforms
    assert "linux" in scanner.supported_platforms
    assert "darwin" not in scanner.supported_platforms


def test_linux_brute_force_detection():
    """Many failed logins should produce CRITICAL finding."""
    scanner = LogAnalysisScanner(_make_config())

    fake_log = "\n".join(
        [f"Failed password for invalid user admin from 192.168.1.{i % 10} port 22 ssh2"
         for i in range(60)]
    )

    with patch("scanners.log_analysis_scanner._run_cmd", return_value=(True, fake_log)):
        findings = scanner._scan_linux_logs()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "brute force" in critical[0].title.lower()


def test_linux_clean_logs():
    """Empty log should produce INFO clean finding."""
    scanner = LogAnalysisScanner(_make_config())

    with patch("scanners.log_analysis_scanner._run_cmd", return_value=(True, "no auth events")):
        findings = scanner._scan_linux_logs()
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) >= 1


def test_linux_root_login_detected():
    """Direct root SSH login should produce HIGH finding."""
    scanner = LogAnalysisScanner(_make_config())

    fake_log = "Accepted publickey for root from 10.0.0.5 port 22 ssh2\n" * 3

    with patch("scanners.log_analysis_scanner._run_cmd", return_value=(True, fake_log)):
        findings = scanner._scan_linux_logs()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert any("root" in f.title.lower() for f in high)


def test_linux_no_log_access():
    """Unable to read logs should produce LOW finding."""
    scanner = LogAnalysisScanner(_make_config())

    with patch("scanners.log_analysis_scanner._run_cmd", return_value=(False, "")):
        findings = scanner._scan_linux_logs()
        assert len(findings) >= 1
        assert any("unable" in f.title.lower() for f in findings)


if __name__ == "__main__":
    test_scanner_properties()
    test_linux_brute_force_detection()
    test_linux_clean_logs()
    test_linux_root_login_detected()
    test_linux_no_log_access()
    print("All log analysis scanner tests passed!")
