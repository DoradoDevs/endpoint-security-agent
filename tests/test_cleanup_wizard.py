"""Tests for the Interactive Cleanup Wizard."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, Severity
from core.telemetry import Finding, ScanResult, SystemInfo
from cli.cleanup_wizard import CleanupWizard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
    category: str = "Test",
    scanner: str = "TestScanner",
    description: str = "A test finding description for unit tests",
    remediation: str = "Apply the recommended fix",
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=category,
        scanner=scanner,
        remediation=remediation,
        evidence=evidence or {},
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        system_info=SystemInfo(hostname="test-host"),
        findings=findings or [],
        risk_score=30.0,
        risk_grade="C",
        scan_duration_seconds=1.0,
    )


def _build_wizard(console: MagicMock | None = None) -> CleanupWizard:
    """Create a wizard with a mocked console."""
    config = AgentConfig()
    con = console or MagicMock()
    return CleanupWizard(config=config, console=con)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCleanupWizardNoFindings:

    @patch("core.agent.SentinelAgent")
    def test_wizard_no_findings(self, mock_agent_cls):
        """When scan returns 0 findings the wizard returns all-zero stats."""
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        wizard = _build_wizard(console)

        stats = wizard.run()

        assert stats["fixed"] == 0
        assert stats["skipped"] == 0
        assert stats["allowlisted"] == 0
        # Verify it printed the "clean" message
        printed_args = [str(c) for c in console.print.call_args_list]
        clean_printed = any("clean" in s.lower() or "no security issues" in s.lower() for s in printed_args)
        assert clean_printed, "Expected a 'clean' message to be printed"


class TestCleanupWizardSkipAll:

    @patch("core.agent.SentinelAgent")
    def test_wizard_skip_all(self, mock_agent_cls):
        """Pressing 's' for every finding skips them all."""
        findings = [
            _make_finding("Issue A", severity=Severity.HIGH),
            _make_finding("Issue B", severity=Severity.MEDIUM),
            _make_finding("Issue C", severity=Severity.LOW),
        ]
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result(findings)
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        stats = wizard.run()

        assert stats["skipped"] == 3
        assert stats["fixed"] == 0
        assert stats["allowlisted"] == 0


class TestCleanupWizardQuitEarly:

    @patch("core.agent.SentinelAgent")
    def test_wizard_quit_early(self, mock_agent_cls):
        """Pressing 'q' on the first finding stops the wizard immediately."""
        findings = [
            _make_finding("Issue A", severity=Severity.CRITICAL),
            _make_finding("Issue B", severity=Severity.HIGH),
            _make_finding("Issue C", severity=Severity.MEDIUM),
        ]
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result(findings)
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "q"

        wizard = _build_wizard(console)
        stats = wizard.run()

        # Only the first finding was presented; user quit before acting on the rest
        assert stats["fixed"] == 0
        assert stats["skipped"] == 0
        assert stats["allowlisted"] == 0
        # input should have been called only once (for the first finding)
        assert console.input.call_count == 1


class TestCleanupWizardAllowlist:

    @patch("cli.cleanup_wizard.AllowlistManager", create=True)
    @patch("core.agent.SentinelAgent")
    def test_wizard_allowlist_by_path(self, mock_agent_cls, mock_allowlist_cls):
        """Pressing 'a' on a finding with a path in evidence calls AllowlistManager.add_path."""
        finding = _make_finding(
            "Suspicious file",
            severity=Severity.HIGH,
            evidence={"path": "/tmp/suspicious.bin"},
        )
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        mock_entry = MagicMock()
        mock_entry.id = "allow-001"
        mock_mgr = MagicMock()
        mock_mgr.add_path.return_value = mock_entry
        mock_allowlist_cls.return_value = mock_mgr

        console = MagicMock()
        console.input.return_value = "a"

        wizard = _build_wizard(console)

        # Patch the import inside _allowlist_finding so it uses our mock
        with patch.dict("sys.modules", {"core.allowlist": MagicMock(AllowlistManager=mock_allowlist_cls)}):
            stats = wizard.run()

        assert stats["allowlisted"] == 1
        assert stats["skipped"] == 0

    @patch("core.agent.SentinelAgent")
    def test_wizard_allowlist_no_evidence(self, mock_agent_cls):
        """Pressing 'a' with empty evidence falls back to skipped."""
        finding = _make_finding("Mystery issue", severity=Severity.MEDIUM, evidence={})
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "a"

        wizard = _build_wizard(console)

        # The import of core.allowlist will succeed with our mock
        with patch.dict("sys.modules", {"core.allowlist": MagicMock(AllowlistManager=MagicMock())}):
            stats = wizard.run()

        assert stats["allowlisted"] == 0
        assert stats["skipped"] == 1

    @patch("core.agent.SentinelAgent")
    def test_wizard_allowlist_import_error(self, mock_agent_cls):
        """If AllowlistManager cannot be imported, finding is skipped."""
        finding = _make_finding(
            "Some finding",
            severity=Severity.HIGH,
            evidence={"path": "/etc/shadow"},
        )
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "a"

        wizard = _build_wizard(console)

        # Force ImportError on the allowlist import
        with patch.dict("sys.modules", {"core.allowlist": None}):
            stats = wizard.run()

        assert stats["allowlisted"] == 0
        assert stats["skipped"] == 1


class TestCleanupWizardFix:

    @patch("core.agent.SentinelAgent")
    def test_wizard_fix_confirmed(self, mock_agent_cls):
        """Pressing 'f' then 'y' to confirm counts as fixed."""
        finding = _make_finding("Bad process", severity=Severity.HIGH, evidence={"pid": 1234})
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        # First input: 'f' (fix), second input: 'y' (confirm)
        console.input.side_effect = ["f", "y"]

        mock_response_engine = MagicMock()
        mock_response_engine.respond_to_finding.return_value = [
            {"action_name": "kill_process", "target": "pid:1234"}
        ]

        mock_response_mod = MagicMock()
        mock_response_mod.ResponseEngine.return_value = mock_response_engine

        wizard = _build_wizard(console)

        with patch.dict("sys.modules", {"response.engine": mock_response_mod}):
            stats = wizard.run()

        assert stats["fixed"] == 1
        assert stats["skipped"] == 0

    @patch("core.agent.SentinelAgent")
    def test_wizard_fix_declined(self, mock_agent_cls):
        """Pressing 'f' then 'n' to decline counts as skipped."""
        finding = _make_finding("Bad process", severity=Severity.HIGH, evidence={"pid": 1234})
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.side_effect = ["f", "n"]

        mock_response_engine = MagicMock()
        mock_response_engine.respond_to_finding.return_value = [
            {"action_name": "kill_process", "target": "pid:1234"}
        ]

        mock_response_mod = MagicMock()
        mock_response_mod.ResponseEngine.return_value = mock_response_engine

        wizard = _build_wizard(console)

        with patch.dict("sys.modules", {"response.engine": mock_response_mod}):
            stats = wizard.run()

        assert stats["fixed"] == 0
        assert stats["skipped"] == 1

    @patch("core.agent.SentinelAgent")
    def test_wizard_fix_import_error(self, mock_agent_cls):
        """If ResponseEngine cannot be imported, finding is skipped."""
        finding = _make_finding("Threat", severity=Severity.CRITICAL)
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "f"

        wizard = _build_wizard(console)

        # Force ImportError on response.engine import
        with patch.dict("sys.modules", {"response.engine": None}):
            stats = wizard.run()

        assert stats["fixed"] == 0
        assert stats["skipped"] == 1


class TestCleanupWizardDetailsThenSkip:

    @patch("core.agent.SentinelAgent")
    def test_wizard_details_then_skip(self, mock_agent_cls):
        """Pressing 'd' shows details, then 's' skips the finding."""
        finding = _make_finding(
            "Open port",
            severity=Severity.MEDIUM,
            category="Network Security",
            evidence={"port": 8080, "service": "http-proxy"},
        )
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result([finding])
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        # First call: 'd' (details), second call: 's' (skip)
        console.input.side_effect = ["d", "s"]

        wizard = _build_wizard(console)
        stats = wizard.run()

        assert stats["skipped"] == 1
        assert stats["fixed"] == 0
        # Console.print should have been called with a Table (details panel)
        table_printed = any(
            isinstance(c.args[0], __import__("rich.table", fromlist=["Table"]).Table)
            for c in console.print.call_args_list
            if c.args
        )
        assert table_printed, "Expected a Rich Table to be printed for details view"


class TestReviewFindingDisplay:

    def test_severity_critical_styling(self):
        """CRITICAL findings should use 'bold red' styling."""
        finding = _make_finding("Critical vuln", severity=Severity.CRITICAL)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        result = wizard._review_finding(finding, 1, 1)

        assert result is True
        # Check that the print call included 'bold red' for CRITICAL
        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "bold red" in printed

    def test_severity_high_styling(self):
        """HIGH findings should use 'bold yellow' styling."""
        finding = _make_finding("High risk", severity=Severity.HIGH)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 1, 1)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "bold yellow" in printed

    def test_severity_medium_styling(self):
        """MEDIUM findings should use 'yellow' styling."""
        finding = _make_finding("Medium concern", severity=Severity.MEDIUM)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 1, 1)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "yellow" in printed

    def test_severity_low_styling(self):
        """LOW findings should use 'blue' styling."""
        finding = _make_finding("Low priority", severity=Severity.LOW)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 1, 1)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "blue" in printed

    def test_severity_info_styling(self):
        """INFO findings should use 'dim' styling."""
        finding = _make_finding("Info note", severity=Severity.INFO)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 1, 1)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "dim" in printed

    def test_index_and_total_displayed(self):
        """The (index/total) counter should appear in the output."""
        finding = _make_finding("Some issue", severity=Severity.MEDIUM)
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 3, 10)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "(3/10)" in printed

    def test_remediation_displayed_when_present(self):
        """Remediation text should be printed when present on the finding."""
        finding = _make_finding("Issue", severity=Severity.HIGH, remediation="Update the package")
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard._review_finding(finding, 1, 1)

        printed = " ".join(str(c) for c in console.print.call_args_list)
        assert "Update the package" in printed

    def test_no_remediation_still_works(self):
        """Findings without remediation text should not crash."""
        finding = _make_finding("Issue", severity=Severity.LOW)
        finding.remediation = ""
        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        result = wizard._review_finding(finding, 1, 1)
        assert result is True


class TestReviewFindingEdgeCases:

    def test_eof_returns_false(self):
        """EOFError during input should cause _review_finding to return False."""
        finding = _make_finding("Issue", severity=Severity.MEDIUM)
        console = MagicMock()
        console.input.side_effect = EOFError()

        wizard = _build_wizard(console)
        result = wizard._review_finding(finding, 1, 1)
        assert result is False

    def test_keyboard_interrupt_returns_false(self):
        """KeyboardInterrupt during input should cause _review_finding to return False."""
        finding = _make_finding("Issue", severity=Severity.MEDIUM)
        console = MagicMock()
        console.input.side_effect = KeyboardInterrupt()

        wizard = _build_wizard(console)
        result = wizard._review_finding(finding, 1, 1)
        assert result is False

    def test_invalid_then_valid_input(self):
        """Invalid input should re-prompt; valid input should be accepted."""
        finding = _make_finding("Issue", severity=Severity.MEDIUM)
        console = MagicMock()
        console.input.side_effect = ["x", "z", "s"]

        wizard = _build_wizard(console)
        result = wizard._review_finding(finding, 1, 1)

        assert result is True
        assert wizard._stats["skipped"] == 1
        # Should have been called 3 times (two invalid + one valid)
        assert console.input.call_count == 3

    @patch("core.agent.SentinelAgent")
    def test_findings_sorted_by_severity(self, mock_agent_cls):
        """Findings should be presented in severity order (highest first)."""
        findings = [
            _make_finding("Low item", severity=Severity.LOW),
            _make_finding("Critical item", severity=Severity.CRITICAL),
            _make_finding("Medium item", severity=Severity.MEDIUM),
        ]
        mock_agent = MagicMock()
        mock_agent.scan.return_value = _make_scan_result(findings)
        mock_agent_cls.return_value = mock_agent

        console = MagicMock()
        console.input.return_value = "s"

        wizard = _build_wizard(console)
        wizard.run()

        # Extract the finding titles from print calls in order
        titles_seen = []
        for c in console.print.call_args_list:
            if c.args:
                text = str(c.args[0])
                for f in findings:
                    if f.title in text and f.title not in titles_seen:
                        titles_seen.append(f.title)
        assert titles_seen == ["Critical item", "Medium item", "Low item"]
