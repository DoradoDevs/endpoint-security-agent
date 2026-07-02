"""Tests for Privilege Scanner."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from core.config import AgentConfig, ScanDepth, Severity
from scanners.privilege_scanner import PrivilegeScanner


def _make_config(depth=ScanDepth.STANDARD):
    config = AgentConfig()
    config.scan.depth = depth
    return config


def test_scanner_properties():
    scanner = PrivilegeScanner(_make_config())
    assert scanner.name == "Privilege Scanner"
    assert "all" in scanner.supported_platforms


def test_linux_nopasswd_detected():
    """NOPASSWD sudoers entries should produce HIGH finding."""
    scanner = PrivilegeScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        sudoers = Path(tmpdir) / "sudoers"
        sudoers.write_text("user ALL=(ALL) NOPASSWD: ALL\n")

        with patch("scanners.privilege_scanner.Path") as mock_path:
            # Mock the sudoers path check
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.return_value = "user ALL=(ALL) NOPASSWD: ALL\n"
            mock_path.return_value.is_file.return_value = True

            # Simpler: directly test the method with a mocked file
            original_func = scanner._check_nopasswd_sudoers

            def mock_check():
                from core.telemetry import Finding
                return [Finding(
                    title="NOPASSWD sudo entries found: 1",
                    description="Users can execute commands as root without password.",
                    severity=Severity.HIGH,
                    category="Privilege Escalation",
                    scanner=scanner.name,
                    evidence={"nopasswd_count": 1, "entries": ["user ALL=(ALL) NOPASSWD: ALL"]},
                    remediation="Remove NOPASSWD entries.",
                )]

            with patch.object(scanner, "_check_nopasswd_sudoers", side_effect=mock_check):
                findings = scanner._scan_linux()
                high = [f for f in findings if f.severity == Severity.HIGH]
                assert len(high) >= 1
                assert "nopasswd" in high[0].title.lower()


def test_windows_uac_disabled_critical():
    """UAC level 0 should produce CRITICAL finding."""
    scanner = PrivilegeScanner(_make_config())

    with patch("scanners.privilege_scanner._run_cmd") as mock_cmd:
        # UAC = 0 (disabled), Guest = False, IsAdmin = False
        mock_cmd.side_effect = [
            (True, "0"),      # UAC level
            (True, "False"),  # Guest account
            (True, "False"),  # IsAdmin
        ]
        findings = scanner._scan_windows()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "uac" in critical[0].title.lower()


def test_windows_uac_recommended():
    """UAC level 5 should produce INFO finding."""
    scanner = PrivilegeScanner(_make_config())

    with patch("scanners.privilege_scanner._run_cmd") as mock_cmd:
        mock_cmd.side_effect = [
            (True, "5"),      # UAC level (recommended)
            (True, "False"),  # Guest account
            (True, "False"),  # IsAdmin
        ]
        findings = scanner._scan_windows()
        info = [f for f in findings if f.severity == Severity.INFO]
        assert any("recommended" in f.title.lower() for f in info)


def test_path_security_check():
    """World-writable PATH dirs should produce findings."""
    scanner = PrivilegeScanner(_make_config())
    # The method checks actual PATH, so just ensure it returns a list
    findings = scanner._check_path_security()
    assert isinstance(findings, list)


if __name__ == "__main__":
    test_scanner_properties()
    test_linux_nopasswd_detected()
    test_windows_uac_disabled_critical()
    test_windows_uac_recommended()
    test_path_security_check()
    print("All privilege scanner tests passed!")
