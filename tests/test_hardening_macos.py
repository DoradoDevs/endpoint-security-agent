"""Tests for remediation.macos_hardening — macOS Hardening Actions."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig


class TestMacOSHardening:

    def _get_actions(self):
        from remediation.macos_hardening import get_macos_actions
        return get_macos_actions(AgentConfig())

    def test_actions_count(self):
        actions = self._get_actions()
        assert len(actions) >= 8

    def test_all_actions_have_required_fields(self):
        for action in self._get_actions():
            assert action.name
            assert action.description
            assert action.severity in ("critical", "high", "medium", "low")
            assert callable(action.check_fn)
            assert callable(action.apply_fn)
            assert action.platform == "darwin"

    @patch("remediation.macos_hardening._run_cmd")
    def test_firewall_check_disabled(self, mock_cmd):
        from remediation.macos_hardening import _MacOSHardening
        engine = _MacOSHardening()
        mock_cmd.return_value = (True, "Firewall is disabled. (State = 0)")

        needed, reason = engine._check_firewall()
        assert needed is True

    @patch("remediation.macos_hardening._run_cmd")
    def test_firewall_check_enabled(self, mock_cmd):
        from remediation.macos_hardening import _MacOSHardening
        engine = _MacOSHardening()
        mock_cmd.return_value = (True, "Firewall is enabled. (State = 1)")

        needed, reason = engine._check_firewall()
        assert needed is False

    @patch("remediation.macos_hardening._run_cmd")
    def test_gatekeeper_disabled(self, mock_cmd):
        from remediation.macos_hardening import _MacOSHardening
        engine = _MacOSHardening()
        mock_cmd.return_value = (True, "assessments disabled")

        needed, reason = engine._check_gatekeeper()
        assert needed is True

    @patch("remediation.macos_hardening._run_cmd")
    def test_filevault_off(self, mock_cmd):
        from remediation.macos_hardening import _MacOSHardening
        engine = _MacOSHardening()
        mock_cmd.return_value = (True, "FileVault is Off.")

        needed, reason = engine._check_filevault()
        assert needed is True

    @patch("remediation.macos_hardening._run_cmd")
    def test_remote_login_on(self, mock_cmd):
        from remediation.macos_hardening import _MacOSHardening
        engine = _MacOSHardening()
        mock_cmd.return_value = (True, "Remote Login: On")

        needed, reason = engine._check_remote_login()
        assert needed is True

    def test_rollback_available_for_remote_login(self):
        actions = self._get_actions()
        ssh_action = next(a for a in actions if "Remote Login" in a.name)
        assert ssh_action.rollback_fn is not None
