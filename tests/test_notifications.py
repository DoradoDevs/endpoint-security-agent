"""Tests for core.notifications — Desktop Notification System."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.notifications import NotificationManager


class TestNotificationManager:
    """Notification system tests."""

    def test_init(self):
        nm = NotificationManager()
        assert nm.log is not None

    @patch("core.notifications.platform.system", return_value="Windows")
    @patch.object(NotificationManager, "_windows_notify", return_value=True)
    def test_notify_windows(self, mock_win, _plat):
        nm = NotificationManager()
        assert nm.notify("Test", "Message") is True
        mock_win.assert_called_once_with("Test", "Message")

    @patch("core.notifications.platform.system", return_value="Darwin")
    @patch.object(NotificationManager, "_macos_notify", return_value=True)
    def test_notify_macos(self, mock_mac, _plat):
        nm = NotificationManager()
        assert nm.notify("Test", "Message") is True
        mock_mac.assert_called_once_with("Test", "Message")

    @patch("core.notifications.platform.system", return_value="Linux")
    @patch.object(NotificationManager, "_linux_notify", return_value=True)
    def test_notify_linux(self, mock_linux, _plat):
        nm = NotificationManager()
        assert nm.notify("Test", "Message") is True
        mock_linux.assert_called_once_with("Test", "Message")

    @patch("core.notifications.platform.system", return_value="FreeBSD")
    def test_notify_unsupported(self, _plat):
        nm = NotificationManager()
        assert nm.notify("Test", "Message") is False

    @patch("core.notifications.platform.system", return_value="Windows")
    @patch.object(NotificationManager, "_windows_notify", side_effect=Exception("boom"))
    def test_notify_exception(self, _win, _plat):
        nm = NotificationManager()
        assert nm.notify("Test", "Message") is False

    def test_escape_ps(self):
        assert NotificationManager._escape_ps("it's a test") == "it''s a test"
        assert NotificationManager._escape_ps('say "hello"') == 'say `"hello`"'

    def test_escape_applescript(self):
        assert NotificationManager._escape_applescript('say "hi"') == 'say \\"hi\\"'
        assert NotificationManager._escape_applescript("back\\slash") == "back\\\\slash"

    @patch("core.notifications.subprocess.run")
    def test_linux_notify_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        nm = NotificationManager()
        assert nm._linux_notify("Title", "Body") is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "notify-send"
        assert "Title" in args
        assert "Body" in args

    @patch("core.notifications.subprocess.run", side_effect=FileNotFoundError)
    def test_linux_notify_no_binary(self, mock_run):
        nm = NotificationManager()
        assert nm._linux_notify("Title", "Body") is False

    @patch("core.notifications.subprocess.run")
    def test_macos_notify_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        nm = NotificationManager()
        assert nm._macos_notify("Title", "Body") is True
        args = mock_run.call_args[0][0]
        assert args[0] == "osascript"

    @patch("core.notifications.subprocess.run")
    def test_windows_toast_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        nm = NotificationManager()
        assert nm._windows_notify("Title", "Body") is True
        args = mock_run.call_args[0][0]
        assert args[0] == "powershell"

    @patch("core.notifications.subprocess.run", side_effect=FileNotFoundError)
    def test_windows_notify_all_fail(self, mock_run):
        nm = NotificationManager()
        assert nm._windows_notify("Title", "Body") is False
