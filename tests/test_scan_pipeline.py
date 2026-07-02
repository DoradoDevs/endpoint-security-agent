"""Integration tests for the scan pipeline: config -> scheduler -> scanners -> risk -> report."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig, ScanDepth, Severity


class TestScanPipeline:
    """Integration tests for the full scan pipeline."""

    @patch("core.scheduler.psutil")
    @patch("core.scheduler.platform")
    def test_scheduler_collects_system_info(self, mock_platform, mock_psutil):
        from core.scheduler import ScanScheduler

        mock_platform.uname.return_value = MagicMock(
            node="test-host", system="Windows", release="10",
            version="10.0.22631", machine="AMD64",
        )
        mock_platform.processor.return_value = "Intel64"
        mock_platform.platform.return_value = "Windows-10-22631"
        mock_platform.system.return_value = "Windows"
        mock_psutil.virtual_memory.return_value = MagicMock(total=16 * 1024**3)
        mock_psutil.cpu_count.return_value = 8

        config = AgentConfig()
        scheduler = ScanScheduler(config)
        info = scheduler.collect_system_info()

        assert info.hostname == "test-host"
        assert info.cpu_count == 8
        assert info.total_memory_gb > 0

    @patch("core.scheduler.psutil")
    @patch("core.scheduler.platform")
    def test_scheduler_discovers_core_scanners(self, mock_platform, mock_psutil):
        from core.scheduler import ScanScheduler

        mock_platform.system.return_value = "Windows"

        config = AgentConfig()
        scheduler = ScanScheduler(config)
        scanners = scheduler.discover_scanners()

        # Core scanners should always be present
        scanner_names = [s.name for s in scanners]
        assert "Process Scanner" in scanner_names
        assert "Network Scanner" in scanner_names

    @patch("core.scheduler.psutil")
    @patch("core.scheduler.platform")
    def test_severity_filtering(self, mock_platform, mock_psutil):
        """Test that min_severity filters out lower-priority findings."""
        from core.scheduler import ScanScheduler
        from core.telemetry import Finding

        mock_platform.system.return_value = "Windows"
        mock_platform.uname.return_value = MagicMock(
            node="test", system="Windows", release="10",
            version="10.0.22631", machine="AMD64",
        )
        mock_platform.processor.return_value = "Intel"
        mock_platform.platform.return_value = "Windows-10"
        mock_psutil.virtual_memory.return_value = MagicMock(total=8 * 1024**3)
        mock_psutil.cpu_count.return_value = 4

        config = AgentConfig()
        config.scan.min_severity = "high"

        scheduler = ScanScheduler(config)

        # Mock all scanners to return controlled findings
        mock_scanner = MagicMock()
        mock_scanner.name = "MockScanner"
        mock_scanner.supported_platforms = ["windows", "darwin", "linux"]
        mock_scanner.run.return_value = [
            Finding(title="Critical", description="test", severity=Severity.CRITICAL,
                    category="Test", scanner="Mock"),
            Finding(title="High", description="test", severity=Severity.HIGH,
                    category="Test", scanner="Mock"),
            Finding(title="Low", description="test", severity=Severity.LOW,
                    category="Test", scanner="Mock"),
            Finding(title="Info", description="test", severity=Severity.INFO,
                    category="Test", scanner="Mock"),
        ]

        # discover_scanners sets self.scanners internally, so we need
        # to both patch the method AND set self.scanners directly
        scheduler.scanners = [mock_scanner]
        with patch.object(scheduler, 'discover_scanners', return_value=[mock_scanner]):
            result = scheduler.run_scan()

        # Low and Info should be filtered out
        finding_titles = [f.title for f in result.findings]
        assert "Critical" in finding_titles
        assert "High" in finding_titles
        assert "Low" not in finding_titles
        assert "Info" not in finding_titles


class TestRiskEngineIntegration:
    """Test risk scoring with realistic findings."""

    def test_risk_score_increases_with_severity(self):
        from reporting.risk_engine import RiskEngine
        from core.telemetry import Finding, ScanResult, SystemInfo
        from core.config import Severity

        engine = RiskEngine()
        sys_info = SystemInfo(hostname="test", os_name="Test", os_version="1.0")

        # Low-risk findings
        low_findings = [
            Finding(title="Info", description="ok", severity=Severity.INFO,
                    category="Inventory", scanner="Test"),
        ]
        low_scan = ScanResult(
            system_info=sys_info, findings=low_findings,
            risk_score=0, risk_grade="A+", scanners_run=["Test"],
            errors=[], scan_duration_seconds=1.0,
        )
        low_score, low_grade = engine.calculate(low_scan)

        # High-risk findings
        high_findings = [
            Finding(title="Critical 1", description="bad", severity=Severity.CRITICAL,
                    category="Malware Indicators", scanner="Test"),
            Finding(title="Critical 2", description="worse", severity=Severity.CRITICAL,
                    category="Network Security", scanner="Test"),
        ]
        high_scan = ScanResult(
            system_info=sys_info, findings=high_findings,
            risk_score=0, risk_grade="F", scanners_run=["Test"],
            errors=[], scan_duration_seconds=1.0,
        )
        high_score, high_grade = engine.calculate(high_scan)

        assert high_score > low_score
