"""Tests for the Process Response Handler."""

from unittest.mock import patch, MagicMock

import psutil

from core.config import Severity
from core.telemetry import Finding
from response.actions.process_response import (
    ProcessResponseHandler,
    SYSTEM_PROCESS_SAFELIST_WINDOWS,
    SYSTEM_PROCESS_SAFELIST_UNIX,
)


class TestProcessResponseHandler:
    """Tests for ProcessResponseHandler."""

    def _make_finding(
        self,
        category: str = "Malware Indicators",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            title="Suspicious process",
            description="Test",
            severity=Severity.HIGH,
            category=category,
            scanner="TestScanner",
            evidence=evidence or {},
        )

    def test_safelist_windows_includes_critical(self):
        """Windows safelist must include critical system processes."""
        for name in ("csrss.exe", "lsass.exe", "svchost.exe", "services.exe"):
            assert name in SYSTEM_PROCESS_SAFELIST_WINDOWS

    def test_safelist_unix_includes_critical(self):
        """Unix safelist must include critical system processes."""
        for name in ("init", "systemd", "sshd", "launchd"):
            assert name in SYSTEM_PROCESS_SAFELIST_UNIX

    def test_is_applicable_with_pid(self):
        """Handler should be applicable when category matches and PID present."""
        handler = ProcessResponseHandler()
        f = self._make_finding(category="Malware Indicators", evidence={"pid": 123, "name": "evil"})
        assert handler.is_applicable(f) is True

    def test_not_applicable_without_pid(self):
        """Handler should not be applicable without PID in evidence."""
        handler = ProcessResponseHandler()
        f = self._make_finding(category="Malware Indicators", evidence={"name": "evil"})
        assert handler.is_applicable(f) is False

    def test_not_applicable_wrong_category(self):
        """Handler should not be applicable for non-matching categories."""
        handler = ProcessResponseHandler()
        f = self._make_finding(category="Network Security", evidence={"pid": 123})
        assert handler.is_applicable(f) is False

    def test_is_applicable_threat_intel(self):
        """Handler should be applicable for Threat Intelligence category."""
        handler = ProcessResponseHandler()
        f = self._make_finding(category="Threat Intelligence", evidence={"pid": 123, "name": "evil"})
        assert handler.is_applicable(f) is True

    def test_can_respond_no_pid(self):
        """Cannot respond without PID."""
        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={})
        can, reason = handler.can_respond(f)
        assert can is False
        assert "No PID" in reason

    @patch("response.actions.process_response.platform")
    def test_can_respond_safelist_blocked(self, mock_platform):
        """Should reject processes on the safelist."""
        mock_platform.system.return_value = "Windows"
        handler = ProcessResponseHandler()
        handler.safelist = SYSTEM_PROCESS_SAFELIST_WINDOWS
        f = self._make_finding(evidence={"pid": 4, "name": "csrss.exe"})
        can, reason = handler.can_respond(f)
        assert can is False
        assert "safelist" in reason

    @patch("psutil.Process")
    def test_can_respond_pid_mismatch(self, mock_proc_cls):
        """Should reject if PID now maps to a different process."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "innocent.exe"
        mock_proc_cls.return_value = mock_proc

        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 999, "name": "evil.exe"})
        can, reason = handler.can_respond(f)
        assert can is False
        assert "no longer matches" in reason

    @patch("psutil.Process")
    def test_can_respond_process_gone(self, mock_proc_cls):
        """Should handle process that no longer exists."""
        mock_proc_cls.side_effect = psutil.NoSuchProcess(999)
        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 999, "name": "evil.exe"})
        can, reason = handler.can_respond(f)
        assert can is False
        assert "no longer exists" in reason

    @patch("psutil.Process")
    def test_can_respond_success(self, mock_proc_cls):
        """Should allow kill when PID matches expected name."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "evil.exe"
        mock_proc_cls.return_value = mock_proc

        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 999, "name": "evil.exe"})
        can, reason = handler.can_respond(f)
        assert can is True
        assert "can be terminated" in reason

    @patch("psutil.Process")
    def test_execute_success(self, mock_proc_cls):
        """Should terminate the process successfully."""
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mock_proc_cls.return_value = mock_proc

        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 123, "name": "evil.exe"})
        success, msg = handler.execute(f)
        assert success is True
        assert "terminated" in msg
        mock_proc.terminate.assert_called_once()

    @patch("psutil.Process")
    def test_execute_force_kill(self, mock_proc_cls):
        """Should force-kill if terminate times out."""
        mock_proc = MagicMock()
        mock_proc.wait.side_effect = psutil.TimeoutExpired(5)
        mock_proc_cls.return_value = mock_proc

        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 123, "name": "evil.exe"})
        success, msg = handler.execute(f)
        assert success is True
        assert "force-killed" in msg
        mock_proc.kill.assert_called_once()

    @patch("psutil.Process")
    def test_execute_access_denied(self, mock_proc_cls):
        """Should fail gracefully on permission denied."""
        mock_proc = MagicMock()
        mock_proc.terminate.side_effect = psutil.AccessDenied(123)
        mock_proc_cls.return_value = mock_proc

        handler = ProcessResponseHandler()
        f = self._make_finding(evidence={"pid": 123, "name": "evil.exe"})
        success, msg = handler.execute(f)
        assert success is False
        assert "Permission denied" in msg
