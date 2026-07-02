"""
Tests for the YARA Scanner.

Covers YARA rule compilation, IOC hash matching, scan target discovery,
severity mapping, and graceful fallback when yara-python is not installed.
"""

import sys
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, Severity
from core.telemetry import Finding


# ---------------------------------------------------------------------------
# TestYaraScannerCreation
# ---------------------------------------------------------------------------

class TestYaraScannerCreation:
    """Tests for scanner initialization and fallback behavior."""

    def test_scanner_creates_without_yara(self):
        """Scanner should initialize gracefully if yara-python is not installed."""
        from scanners.yara_scanner import YaraScanner
        config = AgentConfig()
        scanner = YaraScanner(config)
        info = scanner.get_info()
        # yara_available depends on whether yara-python is actually installed
        assert "yara_available" in info
        assert "rules_directory" in info

    def test_scanner_accepts_ioc_db(self):
        """Scanner should accept an IOC database."""
        from scanners.yara_scanner import YaraScanner
        mock_db = MagicMock()
        config = AgentConfig()
        scanner = YaraScanner(config, ioc_db=mock_db)
        assert scanner._ioc_db is mock_db

    def test_scanner_properties(self):
        """Scanner properties should return expected values."""
        from scanners.yara_scanner import YaraScanner
        config = AgentConfig()
        scanner = YaraScanner(config)
        assert scanner.name == "YaraScanner"
        assert "YARA" in scanner.description
        assert "all" in scanner.supported_platforms


# ---------------------------------------------------------------------------
# TestIOCHashMatching
# ---------------------------------------------------------------------------

class TestIOCHashMatching:
    """Tests for IOC hash matching in the YARA scanner."""

    def test_ioc_hash_match_produces_finding(self):
        """File with hash matching IOC DB should produce CRITICAL finding."""
        from scanners.yara_scanner import YaraScanner

        # Create a temp file with known content
        content = b"this is known malware content for testing"
        sha256 = hashlib.sha256(content).hexdigest()

        mock_match = MagicMock()
        mock_match.threat_category.value = "trojan"
        mock_match.source = "abuse_ch"

        mock_db = MagicMock()
        mock_db.lookup_hash.return_value = mock_match

        config = AgentConfig()
        scanner = YaraScanner(config, ioc_db=mock_db)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(content)
            filepath = Path(f.name)

        try:
            finding = scanner._match_ioc_hash(filepath, content)
            assert finding is not None
            assert finding.severity == Severity.CRITICAL
            assert "Known malware hash" in finding.title
            assert finding.evidence["sha256"] == sha256
            assert finding.evidence["ioc_match"] is True
        finally:
            filepath.unlink(missing_ok=True)

    def test_no_ioc_match_returns_none(self):
        """File with clean hash should return None."""
        from scanners.yara_scanner import YaraScanner

        mock_db = MagicMock()
        mock_db.lookup_hash.return_value = None

        config = AgentConfig()
        scanner = YaraScanner(config, ioc_db=mock_db)

        content = b"clean file content"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            filepath = Path(f.name)

        try:
            finding = scanner._match_ioc_hash(filepath, content)
            assert finding is None
        finally:
            filepath.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestYaraSeverityMapping
# ---------------------------------------------------------------------------

class TestYaraSeverityMapping:
    """Tests for YARA rule severity derivation."""

    def test_critical_tags(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = ["ransomware"]
        mock_match.meta = {}
        assert YaraScanner._yara_severity(mock_match) == Severity.CRITICAL

    def test_high_tags(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = ["malware"]
        mock_match.meta = {}
        assert YaraScanner._yara_severity(mock_match) == Severity.HIGH

    def test_medium_tags(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = ["suspicious"]
        mock_match.meta = {}
        assert YaraScanner._yara_severity(mock_match) == Severity.MEDIUM

    def test_low_tags(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = ["informational"]
        mock_match.meta = {}
        assert YaraScanner._yara_severity(mock_match) == Severity.LOW

    def test_no_tags_defaults_high(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = []
        mock_match.meta = {}
        assert YaraScanner._yara_severity(mock_match) == Severity.HIGH

    def test_severity_from_meta(self):
        from scanners.yara_scanner import YaraScanner
        mock_match = MagicMock()
        mock_match.tags = []
        mock_match.meta = {"severity": "critical"}
        assert YaraScanner._yara_severity(mock_match) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# TestScanTargets
# ---------------------------------------------------------------------------

class TestScanTargets:
    """Tests for scan target discovery."""

    def test_get_scan_targets_returns_paths(self):
        """Should return a list of Path objects."""
        from scanners.yara_scanner import YaraScanner
        config = AgentConfig()
        scanner = YaraScanner(config)
        targets = scanner._get_scan_targets()
        assert isinstance(targets, list)
        for t in targets:
            assert isinstance(t, Path)


# ---------------------------------------------------------------------------
# TestScanEmptyDir
# ---------------------------------------------------------------------------

class TestScanEmptyDir:
    """Test scanning with empty targets."""

    def test_scan_no_yara_no_ioc_returns_empty(self):
        """Scan without YARA or IOC DB should return no findings."""
        from scanners.yara_scanner import YaraScanner
        config = AgentConfig()
        scanner = YaraScanner(config)
        scanner._yara = None
        scanner._ioc_db = None
        findings = scanner.scan()
        assert findings == []
