"""Tests for File Integrity Scanner."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.config import AgentConfig, ScanDepth, Severity
from scanners.file_integrity_scanner import FileIntegrityScanner, _hash_file


def _make_config(depth=ScanDepth.STANDARD):
    config = AgentConfig()
    config.scan.depth = depth
    return config


def test_scanner_properties():
    scanner = FileIntegrityScanner(_make_config())
    assert scanner.name == "File Integrity Scanner"
    assert "all" in scanner.supported_platforms


def test_first_run_creates_baseline():
    """First scan should create baseline and return INFO finding."""
    config = _make_config()
    scanner = FileIntegrityScanner(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_dir = Path(tmpdir)
        with patch("scanners.file_integrity_scanner._baseline_dir", return_value=baseline_dir):
            with patch.object(scanner, "_get_critical_files", return_value=[]):
                findings = scanner.scan()
                assert len(findings) == 1
                assert findings[0].severity == Severity.INFO
                assert "baseline created" in findings[0].title.lower()


def test_no_changes_reports_clean():
    """Second scan with no changes should report clean."""
    config = _make_config()
    scanner = FileIntegrityScanner(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_dir = Path(tmpdir)
        # Create a test file
        test_file = Path(tmpdir) / "testfile.txt"
        test_file.write_text("hello")

        # Create existing baseline
        baseline = {str(test_file): _hash_file(str(test_file))}
        baseline_file = baseline_dir / "file_hashes.json"
        baseline_file.write_text(json.dumps(baseline))

        with patch("scanners.file_integrity_scanner._baseline_dir", return_value=baseline_dir):
            with patch.object(scanner, "_get_critical_files", return_value=[str(test_file)]):
                findings = scanner.scan()
                info_findings = [f for f in findings if f.severity == Severity.INFO]
                assert any("passed" in f.title.lower() for f in info_findings)


def test_modified_file_detected():
    """Modified file should produce HIGH finding."""
    config = _make_config()
    scanner = FileIntegrityScanner(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_dir = Path(tmpdir)
        test_file = Path(tmpdir) / "testfile.txt"
        test_file.write_text("original content")

        # Create baseline with original hash
        baseline = {str(test_file): _hash_file(str(test_file))}
        baseline_file = baseline_dir / "file_hashes.json"
        baseline_file.write_text(json.dumps(baseline))

        # Modify the file
        test_file.write_text("modified content")

        with patch("scanners.file_integrity_scanner._baseline_dir", return_value=baseline_dir):
            with patch.object(scanner, "_get_critical_files", return_value=[str(test_file)]):
                findings = scanner.scan()
                high_findings = [f for f in findings if f.severity == Severity.HIGH]
                assert len(high_findings) == 1
                assert "modified" in high_findings[0].title.lower()


def test_missing_file_detected():
    """Missing file should produce CRITICAL finding."""
    config = _make_config()
    scanner = FileIntegrityScanner(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_dir = Path(tmpdir)
        fake_path = str(Path(tmpdir) / "nonexistent.txt")

        # Create baseline with a file that no longer exists
        baseline = {fake_path: "abc123"}
        baseline_file = baseline_dir / "file_hashes.json"
        baseline_file.write_text(json.dumps(baseline))

        with patch("scanners.file_integrity_scanner._baseline_dir", return_value=baseline_dir):
            with patch.object(scanner, "_get_critical_files", return_value=[]):
                findings = scanner.scan()
                critical = [f for f in findings if f.severity == Severity.CRITICAL]
                assert len(critical) == 1
                assert "missing" in critical[0].title.lower()


def test_quick_scan_fewer_files():
    """QUICK depth should check fewer files than STANDARD."""
    quick_scanner = FileIntegrityScanner(_make_config(ScanDepth.QUICK))
    std_scanner = FileIntegrityScanner(_make_config(ScanDepth.STANDARD))
    quick_files = quick_scanner._get_critical_files()
    std_files = std_scanner._get_critical_files()
    assert len(quick_files) <= len(std_files)


if __name__ == "__main__":
    test_scanner_properties()
    test_first_run_creates_baseline()
    test_no_changes_reports_clean()
    test_modified_file_detected()
    test_missing_file_detected()
    test_quick_scan_fewer_files()
    print("All file integrity scanner tests passed!")
