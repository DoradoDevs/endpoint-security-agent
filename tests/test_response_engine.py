"""Tests for the Threat Response Engine."""

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.config import AgentConfig, Severity
from core.telemetry import Finding, ScanResult
from response.engine import ThreatResponseEngine
from response.models import ResponseStatus


class TestThreatResponseEngine:
    """Tests for ThreatResponseEngine orchestration."""

    def _make_config(self, profile: str = "fort_knox", dry_run: bool = False) -> AgentConfig:
        config = AgentConfig()
        config.profile = profile
        config.scan.dry_run = dry_run
        return config

    def _make_finding(
        self,
        title: str = "Suspicious process",
        severity: Severity = Severity.HIGH,
        category: str = "Malware Indicators",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            description="Test finding",
            severity=severity,
            category=category,
            scanner="TestScanner",
            evidence=evidence or {},
        )

    def _make_scan_result(self, findings: list[Finding] | None = None) -> ScanResult:
        return ScanResult(
            findings=findings or [],
            risk_score=50.0,
            risk_grade="C",
            scan_duration_seconds=1.0,
        )

    def test_alert_only_policy_skips_all(self):
        """MINIMAL profile should skip all active responses."""
        config = self._make_config(profile="minimal")
        engine = ThreatResponseEngine(config)

        finding = self._make_finding(evidence={"pid": 1234, "name": "evil.exe"})
        result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] == 0
        assert result["total_skipped"] >= 1
        assert result["policy_level"] == "alert_only"

    def test_standard_profile_logs_only(self):
        """STANDARD profile should skip active responses (log_and_alert)."""
        config = self._make_config(profile="standard")
        engine = ThreatResponseEngine(config)

        finding = self._make_finding(evidence={"pid": 1234, "name": "evil.exe"})
        result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] == 0
        assert result["policy_level"] == "log_and_alert"

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_dry_run_records_without_executing(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """Dry-run mode should record DRY_RUN status."""
        config = self._make_config(profile="fort_knox", dry_run=True)

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = True
        mock_proc.can_respond.return_value = (True, "Can kill")
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = False
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = False
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(evidence={"pid": 1234, "name": "evil.exe"})
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] >= 1
        assert any(r["status"] == "dry_run" for r in result["executed"])
        mock_proc.execute.assert_not_called()

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_auto_respond_executes_process_kill(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """FORT_KNOX profile should auto-respond with process kill."""
        config = self._make_config(profile="fort_knox")

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = True
        mock_proc.can_respond.return_value = (True, "Can kill")
        mock_proc.execute.return_value = (True, "Killed process")
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = False
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = False
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(evidence={"pid": 1234, "name": "evil.exe"})
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] >= 1
        assert any(r["status"] == "executed" for r in result["executed"])
        mock_proc.execute.assert_called_once()

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_network_block_on_threat_intel(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """Network handler should block IPs from threat intel findings."""
        config = self._make_config(profile="fort_knox")

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = False
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = False
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = True
        mock_net.get_ip_from_finding.return_value = "1.2.3.4"
        mock_net.block_ip.return_value = (True, "Blocked 1.2.3.4")
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(
                category="Threat Intelligence",
                evidence={"remote_ip": "1.2.3.4", "ioc_value": "1.2.3.4"},
            )
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] >= 1
        mock_net.block_ip.assert_called_once()

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_file_quarantine_on_malware(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """File handler should quarantine files from malware findings."""
        config = self._make_config(profile="fort_knox")

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = False
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = True
        mock_file.get_filepath_from_finding.return_value = "/tmp/malware.exe"
        mock_file.quarantine.return_value = (True, "File quarantined (ID: abc123)")
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = False
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(
                category="Malware Indicators",
                evidence={"path": "/tmp/malware.exe"},
            )
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] >= 1
        mock_file.quarantine.assert_called_once()

    def test_info_findings_ignored(self):
        """INFO-severity findings should not trigger any response."""
        config = self._make_config(profile="fort_knox")

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(severity=Severity.INFO, evidence={"pid": 1})
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] == 0
        assert result["total_skipped"] == 0

    def test_low_findings_skipped_in_strict(self):
        """STRICT profile requires HIGH+ severity for response."""
        config = self._make_config(profile="strict")

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(
                severity=Severity.LOW,
                evidence={"pid": 1, "name": "test"},
            )
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_actions"] == 0

    def test_empty_scan_result(self):
        """Empty scan results should produce no actions."""
        config = self._make_config(profile="fort_knox")

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            result = engine.respond(self._make_scan_result([]))

        assert result["total_actions"] == 0
        assert result["total_skipped"] == 0
        assert result["total_errors"] == 0

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_failed_action_goes_to_errors(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """Failed response actions should be categorized as errors."""
        config = self._make_config(profile="fort_knox")

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = True
        mock_proc.can_respond.return_value = (True, "Can kill")
        mock_proc.execute.return_value = (False, "Permission denied")
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = False
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = False
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(evidence={"pid": 1234, "name": "evil.exe"})
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_errors"] >= 1

    def test_extract_target_priority(self):
        """_extract_target should prefer pid > remote_ip > path > title."""
        finding = self._make_finding(evidence={"pid": 42, "remote_ip": "1.1.1.1"})
        assert ThreatResponseEngine._extract_target(finding) == "42"

        finding2 = self._make_finding(evidence={"remote_ip": "1.1.1.1", "path": "/tmp/x"})
        assert ThreatResponseEngine._extract_target(finding2) == "1.1.1.1"

        finding3 = self._make_finding(title="MyFinding", evidence={})
        assert ThreatResponseEngine._extract_target(finding3) == "MyFinding"

    @patch("response.engine.ProcessResponseHandler")
    @patch("response.engine.FileQuarantineManager")
    @patch("response.engine.NetworkResponseHandler")
    def test_skipped_when_cannot_respond(
        self, mock_net_cls, mock_file_cls, mock_proc_cls
    ):
        """Process on safelist should produce SKIPPED record."""
        config = self._make_config(profile="fort_knox")

        mock_proc = MagicMock()
        mock_proc.is_applicable.return_value = True
        mock_proc.can_respond.return_value = (False, "Process on safelist")
        mock_proc_cls.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.is_applicable.return_value = False
        mock_file_cls.return_value = mock_file

        mock_net = MagicMock()
        mock_net.is_applicable.return_value = False
        mock_net_cls.return_value = mock_net

        with tempfile.TemporaryDirectory() as tmp:
            engine = ThreatResponseEngine(config)
            engine.audit.log_dir = Path(tmp)
            engine.audit.log_file = Path(tmp) / "audit.jsonl"

            finding = self._make_finding(evidence={"pid": 1, "name": "svchost.exe"})
            result = engine.respond(self._make_scan_result([finding]))

        assert result["total_skipped"] >= 1
        assert result["total_actions"] == 0
