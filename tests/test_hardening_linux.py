"""Tests for remediation.linux_hardening — Linux Hardening Actions."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig


class TestLinuxHardening:

    def _get_actions(self):
        from remediation.linux_hardening import get_linux_actions
        return get_linux_actions(AgentConfig())

    def test_actions_count(self):
        actions = self._get_actions()
        assert len(actions) >= 10

    def test_all_actions_have_required_fields(self):
        for action in self._get_actions():
            assert action.name
            assert action.description
            assert action.severity in ("critical", "high", "medium", "low")
            assert callable(action.check_fn)
            assert callable(action.apply_fn)
            assert action.platform == "linux"

    @patch("remediation.linux_hardening._run_cmd")
    def test_ufw_inactive(self, mock_cmd):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_cmd.return_value = (True, "Status: inactive")

        needed, reason = engine._check_ufw()
        assert needed is True

    @patch("remediation.linux_hardening._run_cmd")
    def test_ufw_active(self, mock_cmd):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_cmd.return_value = (True, "Status: active")

        needed, reason = engine._check_ufw()
        assert needed is False

    @patch("remediation.linux_hardening._read_file")
    def test_ssh_root_login_enabled(self, mock_read):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_read.return_value = "PermitRootLogin yes\nPasswordAuthentication no\n"

        needed, reason = engine._check_ssh_root()
        assert needed is True

    @patch("remediation.linux_hardening._read_file")
    def test_ssh_root_login_disabled(self, mock_read):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_read.return_value = "PermitRootLogin no\nPasswordAuthentication no\n"

        needed, reason = engine._check_ssh_root()
        assert needed is False

    @patch("remediation.linux_hardening._run_cmd")
    def test_fail2ban_not_running(self, mock_cmd):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_cmd.return_value = (False, "Unit fail2ban.service could not be found")

        needed, reason = engine._check_fail2ban()
        assert needed is True

    @patch("remediation.linux_hardening.Path")
    def test_kernel_hardening_missing(self, mock_path):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_path.return_value.exists.return_value = False

        needed, reason = engine._check_kernel_hardening()
        assert needed is True

    @patch("remediation.linux_hardening._read_file")
    def test_ssh_empty_passwords_allowed(self, mock_read):
        from remediation.linux_hardening import _LinuxHardening
        engine = _LinuxHardening()
        mock_read.return_value = "PermitEmptyPasswords yes\n"

        needed, reason = engine._check_ssh_empty_passwords()
        assert needed is True
