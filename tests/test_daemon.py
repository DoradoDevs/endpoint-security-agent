"""Tests for core.daemon — Sentinel Daemon / Continuous Monitoring."""

from __future__ import annotations

import os
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig
from core.daemon import SentinelDaemon, _pid_file


class TestPidFile:
    """PID file path resolution."""

    @patch("core.daemon.platform.system", return_value="Windows")
    def test_pid_file_windows(self, _mock):
        path = _pid_file()
        assert "Sentinel" in str(path)
        assert str(path).endswith("sentinel.pid")

    @patch("core.daemon.platform.system", return_value="Darwin")
    def test_pid_file_macos(self, _mock):
        path = _pid_file()
        assert "Sentinel" in str(path)
        assert str(path).endswith("sentinel.pid")

    @patch("core.daemon.platform.system", return_value="Linux")
    def test_pid_file_linux_user(self, _plat):
        with patch.object(os, "geteuid", return_value=1000, create=True):
            path = _pid_file()
            assert ".sentinel" in str(path)
            assert str(path).endswith("sentinel.pid")


class TestSentinelDaemon:
    """Daemon lifecycle tests."""

    def _make_daemon(self) -> SentinelDaemon:
        config = AgentConfig()
        return SentinelDaemon(config)

    def test_init(self):
        d = self._make_daemon()
        assert d.running is False
        assert d._scan_interval > 0

    @patch("core.daemon.SentinelDaemon._write_pid")
    @patch("core.daemon.SentinelDaemon._remove_pid")
    @patch("core.daemon.SentinelDaemon._run_scan")
    def test_start_stop(self, mock_scan, mock_rm_pid, mock_wr_pid):
        d = self._make_daemon()

        # Start daemon in a thread, then stop it quickly
        def start_daemon():
            d.start()

        t = threading.Thread(target=start_daemon, daemon=True)
        t.start()

        # Give it time to start
        time.sleep(0.3)
        assert d.running is True
        mock_wr_pid.assert_called_once()

        # Stop it
        d._stop_event.set()
        t.join(timeout=5)
        assert d.running is False
        mock_rm_pid.assert_called_once()

    @patch("core.daemon.SentinelDaemon._write_pid")
    @patch("core.daemon.SentinelDaemon._remove_pid")
    @patch("core.daemon.SentinelDaemon._run_scan")
    def test_stop_idempotent(self, mock_scan, mock_rm, mock_wr):
        d = self._make_daemon()
        # Stopping when not running should be a no-op
        d.stop()
        mock_rm.assert_not_called()

    @patch("core.daemon._pid_file")
    def test_is_running_no_pidfile(self, mock_pf):
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_pf.return_value = mock_path
        assert SentinelDaemon.is_running() is False

    @patch("core.daemon._pid_file")
    def test_is_running_stale_pid(self, mock_pf):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "99999999"
        mock_pf.return_value = mock_path

        # os.kill(99999999, 0) should raise OSError
        with patch("os.kill", side_effect=OSError):
            assert SentinelDaemon.is_running() is False

    def test_on_file_change_sends_alert(self):
        d = self._make_daemon()
        with patch.object(d, "_send_alert") as mock_alert:
            d._on_file_change("/etc/hosts", "modified")
            mock_alert.assert_called_once()
            assert "modified" in mock_alert.call_args[0][1]

    def test_get_scan_interval_default(self):
        d = self._make_daemon()
        # Default interval should be at least 60 seconds
        assert d._scan_interval >= 60

    @patch("core.daemon.SentinelDaemon.is_running", return_value=False)
    def test_stop_running_no_pidfile(self, _mock):
        with patch("core.daemon._pid_file") as mock_pf:
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            mock_pf.return_value = mock_path
            assert SentinelDaemon.stop_running() is False
