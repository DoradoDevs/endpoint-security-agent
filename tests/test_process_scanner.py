"""Tests for scanners.process_scanner — Process Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig, ScanDepth
from scanners.process_scanner import ProcessScanner


@pytest.fixture
def scanner():
    return ProcessScanner(AgentConfig())


def _mock_process(name="normal.exe", pid=1000, exe="C:\\Program Files\\App\\normal.exe",
                  username="user", cmdline=None):
    proc = MagicMock()
    proc.info = {
        "name": name,
        "pid": pid,
        "exe": exe,
        "username": username,
        "cmdline": cmdline or [exe],
    }
    return proc


class TestProcessScanner:

    def test_properties(self, scanner):
        assert scanner.name == "Process Scanner"
        assert "all" in scanner.supported_platforms

    @patch("scanners.process_scanner.psutil")
    def test_clean_system_no_findings(self, mock_psutil, scanner):
        mock_psutil.process_iter.return_value = [
            _mock_process("svchost.exe", 400, "C:\\Windows\\System32\\svchost.exe"),
            _mock_process("explorer.exe", 500, "C:\\Windows\\explorer.exe"),
        ]
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception
        mock_psutil.ZombieProcess = Exception

        findings = scanner.scan()
        # Should only have inventory (info) findings
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) == 0

    @patch("scanners.process_scanner.psutil")
    def test_suspicious_process_name_detected(self, mock_psutil, scanner):
        mock_psutil.process_iter.return_value = [
            _mock_process("mimikatz.exe", 666, "C:\\temp\\mimikatz.exe"),
        ]
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception
        mock_psutil.ZombieProcess = Exception

        findings = scanner.scan()
        high_findings = [f for f in findings if f.severity.value in ("critical", "high")]
        assert len(high_findings) >= 1
        assert any("mimikatz" in f.title.lower() or "mimikatz" in f.description.lower()
                    for f in high_findings)

    @patch("scanners.process_scanner.psutil")
    def test_process_in_temp_dir(self, mock_psutil, scanner):
        mock_psutil.process_iter.return_value = [
            _mock_process("suspicious.exe", 777, "/tmp/suspicious.exe"),
        ]
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.AccessDenied = Exception
        mock_psutil.ZombieProcess = Exception

        findings = scanner.scan()
        non_info = [f for f in findings if f.severity.value != "info"]
        assert len(non_info) >= 1

    @patch("scanners.process_scanner.psutil")
    def test_handles_access_denied(self, mock_psutil, scanner):
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})
        mock_psutil.process_iter.return_value = [
            _mock_process("normal.exe", 100, "C:\\app\\normal.exe"),
        ]
        # Should not raise even if some processes are inaccessible
        findings = scanner.scan()
        assert isinstance(findings, list)
