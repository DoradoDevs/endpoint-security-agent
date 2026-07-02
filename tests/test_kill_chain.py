"""Tests for the Kill Chain Analyzer.

All system calls (psutil, subprocess, filesystem) are fully mocked so
the suite runs without real system access.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

import psutil
import pytest

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from response.actions.kill_chain import KillChainAnalyzer, KillChainReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config():
    return AgentConfig()


@pytest.fixture
def analyzer(config):
    return KillChainAnalyzer(config)


@pytest.fixture
def sample_finding():
    return Finding(
        title="Malware detected",
        description="Test malware",
        severity=Severity.CRITICAL,
        category="Malware Indicators",
        scanner="MalwareScanner",
        evidence={"pid": 1234, "path": "/tmp/malware.exe", "sha256": "abc123"},
    )


def _make_finding(severity=Severity.CRITICAL, evidence=None):
    """Convenience factory for tests that need varied findings."""
    return Finding(
        title="Test finding",
        description="test",
        severity=severity,
        category="Malware Indicators",
        scanner="TestScanner",
        evidence=evidence or {},
    )


def _mock_process(
    pid=1234,
    name="malware.exe",
    exe="/tmp/malware.exe",
    cmdline=None,
    create_time=1700000000.0,
    status="running",
    parents=None,
    children=None,
    connections=None,
):
    """Create a mock psutil.Process with sensible defaults."""
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.cmdline.return_value = cmdline or [exe]
    proc.create_time.return_value = create_time
    proc.status.return_value = status
    proc.parents.return_value = parents or []
    proc.children.return_value = children or []
    proc.net_connections.return_value = connections or []
    return proc


# ===================================================================
# TestKillChainReport
# ===================================================================

class TestKillChainReport:
    """Verify the KillChainReport dataclass."""

    def test_creation_with_defaults(self, sample_finding):
        """Report should initialise with empty collections and safe defaults."""
        report = KillChainReport(trigger_finding=sample_finding)
        assert report.trigger_finding is sample_finding
        assert report.process_tree == []
        assert report.related_files == []
        assert report.persistence_entries == []
        assert report.network_targets == []
        assert report.remediation_steps == []
        assert report.auto_cleanable is False
        assert report.risk_level == "low"

    def test_creation_with_values(self, sample_finding):
        """Report should accept explicit values for every field."""
        report = KillChainReport(
            trigger_finding=sample_finding,
            process_tree=[{"pid": 1}],
            related_files=["/tmp/bad.exe"],
            persistence_entries=[{"mechanism": "crontab", "path": "crontab", "command": "x", "detail": "y"}],
            network_targets=["10.0.0.1:443"],
            remediation_steps=["step 1"],
            auto_cleanable=True,
            risk_level="critical",
        )
        assert len(report.process_tree) == 1
        assert report.auto_cleanable is True
        assert report.risk_level == "critical"


# ===================================================================
# TestProcessTreeAnalysis
# ===================================================================

class TestProcessTreeAnalysis:

    @patch("response.actions.kill_chain.psutil.Process")
    def test_full_tree_traced(self, mock_proc_cls, analyzer, sample_finding):
        """Should record the trigger, its parents, and its children."""
        parent = _mock_process(pid=100, name="parent.exe", exe="/usr/bin/parent.exe")
        child = _mock_process(pid=2000, name="child.exe", exe="/tmp/child.exe")
        trigger = _mock_process(
            pid=1234, parents=[parent], children=[child],
        )
        mock_proc_cls.return_value = trigger

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_process_tree(sample_finding, report)

        pids = {p["pid"] for p in report.process_tree}
        assert 1234 in pids
        assert 100 in pids
        assert 2000 in pids
        # Child from /tmp should be flagged suspicious
        child_info = next(p for p in report.process_tree if p["pid"] == 2000)
        assert child_info["suspicious"] is True

    def test_no_pid_in_evidence(self, analyzer):
        """Should gracefully skip when no PID is present."""
        finding = _make_finding(evidence={"path": "/tmp/payload.bin"})
        report = KillChainReport(trigger_finding=finding)
        analyzer._trace_process_tree(finding, report)
        assert report.process_tree == []

    @patch("response.actions.kill_chain.psutil.Process")
    def test_process_gone(self, mock_proc_cls, analyzer, sample_finding):
        """Should handle NoSuchProcess gracefully."""
        mock_proc_cls.side_effect = psutil.NoSuchProcess(1234)
        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_process_tree(sample_finding, report)
        assert report.process_tree == []

    @patch("response.actions.kill_chain.psutil.Process")
    def test_access_denied(self, mock_proc_cls, analyzer, sample_finding):
        """Should handle AccessDenied gracefully."""
        mock_proc_cls.side_effect = psutil.AccessDenied(1234)
        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_process_tree(sample_finding, report)
        assert report.process_tree == []


# ===================================================================
# TestFileArtifactDiscovery
# ===================================================================

class TestFileArtifactDiscovery:

    @patch("response.actions.kill_chain.Path.exists", return_value=True)
    @patch("response.actions.kill_chain.Path.is_file", return_value=True)
    def test_related_files_found(self, _mock_is_file, _mock_exists, analyzer, sample_finding):
        """Should discover files sharing creation time or extension."""
        threat_path = Path("/tmp/malware.exe")
        related_file = MagicMock(spec=Path)
        related_file.is_file.return_value = True
        related_file.suffix = ".exe"
        related_file.stem = "malware_payload"
        related_file.stat.return_value = MagicMock(st_ctime=1700000010.0)
        related_file.__str__ = lambda self: "/tmp/malware_payload.exe"
        related_file.__eq__ = lambda self, other: False

        unrelated_file = MagicMock(spec=Path)
        unrelated_file.is_file.return_value = True
        unrelated_file.suffix = ".txt"
        unrelated_file.stem = "readme"
        unrelated_file.stat.return_value = MagicMock(st_ctime=1600000000.0)
        unrelated_file.__str__ = lambda self: "/tmp/readme.txt"
        unrelated_file.__eq__ = lambda self, other: False

        with (
            patch.object(Path, "stat", return_value=MagicMock(st_ctime=1700000000.0)),
            patch.object(Path, "parent", new_callable=PropertyMock) as mock_parent,
        ):
            parent_dir = MagicMock()
            parent_dir.iterdir.return_value = [related_file, unrelated_file]
            mock_parent.return_value = parent_dir

            report = KillChainReport(trigger_finding=sample_finding)
            analyzer._discover_file_artifacts(sample_finding, report)

        # The threat file itself + the related .exe should be recorded
        assert "/tmp/malware_payload.exe" in report.related_files
        # The unrelated readme.txt should NOT be present
        assert "/tmp/readme.txt" not in report.related_files

    def test_no_path_in_evidence(self, analyzer):
        """Should skip when no file path is in the finding evidence."""
        finding = _make_finding(evidence={"pid": 1234})
        report = KillChainReport(trigger_finding=finding)
        analyzer._discover_file_artifacts(finding, report)
        assert report.related_files == []

    @patch("response.actions.kill_chain.Path.exists", return_value=True)
    @patch("response.actions.kill_chain.Path.is_file", return_value=True)
    def test_directory_scan_error(self, _mock_is_file, _mock_exists, analyzer, sample_finding):
        """Should handle directory scan errors gracefully."""
        with (
            patch.object(Path, "stat", return_value=MagicMock(st_ctime=1700000000.0)),
            patch.object(Path, "parent", new_callable=PropertyMock) as mock_parent,
        ):
            parent_dir = MagicMock()
            parent_dir.iterdir.side_effect = PermissionError("Access denied")
            mock_parent.return_value = parent_dir

            report = KillChainReport(trigger_finding=sample_finding)
            analyzer._discover_file_artifacts(sample_finding, report)

        # The threat file itself should still be recorded
        assert len(report.related_files) >= 1


# ===================================================================
# TestPersistenceTrace
# ===================================================================

class TestPersistenceTrace:

    @patch("response.actions.kill_chain.is_windows", return_value=True)
    @patch("response.actions.kill_chain.is_linux", return_value=False)
    @patch("response.actions.kill_chain.is_macos", return_value=False)
    @patch("response.actions.kill_chain.subprocess.run")
    def test_registry_entry_found(self, mock_run, _m1, _m2, _m3, analyzer, sample_finding):
        """Should detect threat references in Windows registry Run keys."""
        reg_output = r"    MalwareEntry    REG_SZ    C:\tmp\malware.exe"
        mock_run.return_value = MagicMock(
            returncode=0, stdout=reg_output, stderr=""
        )

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_persistence(sample_finding, report)

        assert len(report.persistence_entries) > 0
        assert any(
            e["mechanism"] == "registry_run_key"
            for e in report.persistence_entries
        )

    @patch("response.actions.kill_chain.is_windows", return_value=False)
    @patch("response.actions.kill_chain.is_linux", return_value=True)
    @patch("response.actions.kill_chain.is_macos", return_value=False)
    @patch("response.actions.kill_chain.subprocess.run")
    def test_crontab_entry_found(self, mock_run, _m1, _m2, _m3, analyzer):
        """Should detect threat references in crontab."""
        finding = _make_finding(evidence={"path": "/tmp/backdoor.sh"})
        mock_run.return_value = MagicMock(
            returncode=0, stdout="*/5 * * * * /tmp/backdoor.sh", stderr=""
        )

        with patch.object(Path, "exists", return_value=False):
            report = KillChainReport(trigger_finding=finding)
            analyzer._trace_persistence(finding, report)

        assert any(
            e["mechanism"] == "crontab" for e in report.persistence_entries
        )

    @patch("response.actions.kill_chain.is_windows", return_value=True)
    @patch("response.actions.kill_chain.is_linux", return_value=False)
    @patch("response.actions.kill_chain.is_macos", return_value=False)
    @patch("response.actions.kill_chain.subprocess.run")
    def test_no_persistence_found(self, mock_run, _m1, _m2, _m3, analyzer, sample_finding):
        """Should produce no entries when nothing matches."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="nothing interesting here", stderr=""
        )

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_persistence(sample_finding, report)

        assert report.persistence_entries == []

    @patch("response.actions.kill_chain.is_windows", return_value=True)
    @patch("response.actions.kill_chain.is_linux", return_value=False)
    @patch("response.actions.kill_chain.is_macos", return_value=False)
    @patch("response.actions.kill_chain.subprocess.run")
    def test_command_failure(self, mock_run, _m1, _m2, _m3, analyzer, sample_finding):
        """Should handle subprocess failures gracefully."""
        mock_run.side_effect = FileNotFoundError("reg not found")

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_persistence(sample_finding, report)

        assert report.persistence_entries == []


# ===================================================================
# TestNetworkTrace
# ===================================================================

class TestNetworkTrace:

    @patch("response.actions.kill_chain.psutil.Process")
    def test_active_connections_found(self, mock_proc_cls, analyzer, sample_finding):
        """Should record remote addresses from active connections."""
        conn1 = MagicMock()
        conn1.raddr = SimpleNamespace(ip="10.0.0.5", port=443)
        conn2 = MagicMock()
        conn2.raddr = SimpleNamespace(ip="192.168.1.99", port=8080)
        conn_no_raddr = MagicMock()
        conn_no_raddr.raddr = None

        proc = _mock_process(pid=1234, connections=[conn1, conn2, conn_no_raddr])
        mock_proc_cls.return_value = proc

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_network(sample_finding, report)

        assert "10.0.0.5:443" in report.network_targets
        assert "192.168.1.99:8080" in report.network_targets
        assert len(report.network_targets) == 2

    @patch("response.actions.kill_chain.psutil.Process")
    def test_process_not_running(self, mock_proc_cls, analyzer, sample_finding):
        """Should handle NoSuchProcess when process has exited."""
        mock_proc_cls.side_effect = psutil.NoSuchProcess(1234)

        report = KillChainReport(trigger_finding=sample_finding)
        analyzer._trace_network(sample_finding, report)

        assert report.network_targets == []

    def test_no_network_evidence(self, analyzer):
        """Should skip when no PID is available."""
        finding = _make_finding(evidence={"path": "/tmp/malware.exe"})
        report = KillChainReport(trigger_finding=finding)
        analyzer._trace_network(finding, report)
        assert report.network_targets == []


# ===================================================================
# TestRemediationPlan
# ===================================================================

class TestRemediationPlan:

    def test_full_plan_with_all_components(self, analyzer, sample_finding):
        """Should produce steps for processes, files, persistence, and network."""
        report = KillChainReport(
            trigger_finding=sample_finding,
            process_tree=[
                {"pid": 1234, "name": "malware.exe", "exe_path": "/tmp/malware.exe",
                 "cmdline": [], "create_time": 0, "status": "running", "suspicious": True},
                {"pid": 2000, "name": "child.exe", "exe_path": "/tmp/child.exe",
                 "cmdline": [], "create_time": 0, "status": "running", "suspicious": True},
            ],
            related_files=["/tmp/malware.exe", "/tmp/payload.bin"],
            persistence_entries=[
                {"mechanism": "crontab", "path": "crontab",
                 "command": "/tmp/malware.exe", "detail": "entry"},
            ],
            network_targets=["10.0.0.5:443"],
        )

        analyzer._build_remediation_plan(report)

        assert len(report.remediation_steps) == 5
        assert "Terminate process tree" in report.remediation_steps[0]
        assert "Quarantine files" in report.remediation_steps[1]
        assert "Remove persistence" in report.remediation_steps[2]
        assert "Block network" in report.remediation_steps[3]
        assert "Scan system" in report.remediation_steps[4]

    def test_minimal_plan_single_file(self, analyzer):
        """Should produce a plan for a single file with no other indicators."""
        finding = _make_finding(evidence={"path": "/tmp/suspicious.bin"})
        report = KillChainReport(
            trigger_finding=finding,
            related_files=["/tmp/suspicious.bin"],
        )

        analyzer._build_remediation_plan(report)

        assert any("Quarantine" in s for s in report.remediation_steps)
        assert any("Scan system" in s for s in report.remediation_steps)
        # No process or network steps
        assert not any("Terminate" in s for s in report.remediation_steps)
        assert not any("Block network" in s for s in report.remediation_steps)

    def test_auto_cleanable_logic(self, analyzer, sample_finding):
        """auto_cleanable should be True when all artifacts are from temp dirs."""
        report = KillChainReport(
            trigger_finding=sample_finding,
            process_tree=[
                {"pid": 1234, "name": "malware.exe", "exe_path": "/tmp/malware.exe",
                 "cmdline": [], "create_time": 0, "status": "running", "suspicious": True},
            ],
            related_files=["/tmp/malware.exe", "/tmp/payload.bin"],
        )

        analyzer._assess_auto_cleanable(report)
        assert report.auto_cleanable is True

    def test_not_auto_cleanable_system_process(self, analyzer, sample_finding):
        """auto_cleanable should be False when system-critical processes are involved."""
        report = KillChainReport(
            trigger_finding=sample_finding,
            process_tree=[
                {"pid": 1, "name": "systemd", "exe_path": "/usr/lib/systemd/systemd",
                 "cmdline": [], "create_time": 0, "status": "running", "suspicious": False},
                {"pid": 1234, "name": "malware.exe", "exe_path": "/tmp/malware.exe",
                 "cmdline": [], "create_time": 0, "status": "running", "suspicious": True},
            ],
            related_files=["/tmp/malware.exe"],
        )

        analyzer._assess_auto_cleanable(report)
        assert report.auto_cleanable is False


# ===================================================================
# TestRiskLevel
# ===================================================================

class TestRiskLevel:

    def test_critical_all_indicators(self, analyzer):
        """CRITICAL severity + network + persistence = 'critical' risk."""
        finding = _make_finding(severity=Severity.CRITICAL)
        report = KillChainReport(
            trigger_finding=finding,
            persistence_entries=[{"mechanism": "crontab", "path": "x", "command": "y", "detail": "z"}],
            network_targets=["10.0.0.1:443"],
            related_files=["/tmp/a.exe", "/tmp/b.exe"],
        )

        analyzer._assess_risk(finding, report)
        assert report.risk_level == "critical"

    def test_medium_single_artifact(self, analyzer):
        """MEDIUM severity with a single file and no other indicators."""
        finding = _make_finding(severity=Severity.MEDIUM)
        report = KillChainReport(
            trigger_finding=finding,
            related_files=["/tmp/suspicious.bin"],
        )

        analyzer._assess_risk(finding, report)
        assert report.risk_level == "medium"

    def test_low_no_active_indicators(self, analyzer):
        """INFO severity with nothing active = 'low' risk."""
        finding = _make_finding(severity=Severity.INFO)
        report = KillChainReport(trigger_finding=finding)

        analyzer._assess_risk(finding, report)
        assert report.risk_level == "low"


# ===================================================================
# TestAnalyzeIntegration
# ===================================================================

class TestAnalyzeIntegration:

    @patch("response.actions.kill_chain.psutil.Process")
    @patch("response.actions.kill_chain.is_windows", return_value=False)
    @patch("response.actions.kill_chain.is_linux", return_value=True)
    @patch("response.actions.kill_chain.is_macos", return_value=False)
    @patch("response.actions.kill_chain.subprocess.run")
    def test_full_analyze_flow(
        self, mock_subproc, _is_mac, _is_linux, _is_win, mock_proc_cls,
        analyzer, sample_finding,
    ):
        """Full analyze() should populate every section of the report."""
        conn = MagicMock()
        conn.raddr = SimpleNamespace(ip="10.0.0.5", port=443)
        trigger = _mock_process(
            pid=1234,
            name="malware.exe",
            exe="/tmp/malware.exe",
            connections=[conn],
        )
        mock_proc_cls.return_value = trigger

        # subprocess: crontab -l returns a matching entry
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout="*/5 * * * * /tmp/malware.exe --silent",
            stderr="",
        )

        with (
            patch.object(Path, "exists", return_value=False),
        ):
            report = analyzer.analyze(sample_finding)

        # Process tree should have at least the trigger PID
        assert any(p["pid"] == 1234 for p in report.process_tree)

        # Network targets should include the mocked connection
        assert "10.0.0.5:443" in report.network_targets

        # Persistence should have the crontab entry
        assert any(e["mechanism"] == "crontab" for e in report.persistence_entries)

        # Remediation steps should be populated
        assert len(report.remediation_steps) > 0

        # Risk level should be "critical" (CRITICAL + network + persistence)
        assert report.risk_level == "critical"

    @patch("response.actions.kill_chain.psutil.Process")
    def test_finding_with_no_actionable_evidence(
        self, mock_proc_cls, analyzer,
    ):
        """Analyze with an empty evidence dict should produce a mostly-empty report."""
        finding = _make_finding(severity=Severity.INFO, evidence={})

        report = analyzer.analyze(finding)

        assert report.process_tree == []
        assert report.related_files == []
        assert report.persistence_entries == []
        assert report.network_targets == []
        # Should still have the final "Scan system" step
        assert any("Scan system" in s for s in report.remediation_steps)
        assert report.risk_level == "low"
        assert report.auto_cleanable is False
