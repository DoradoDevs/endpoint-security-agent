"""Tests for remediation.windows_hardening — Windows Hardening Actions."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig


class TestWindowsHardening:

    def _get_actions(self):
        from remediation.windows_hardening import get_windows_actions
        return get_windows_actions(AgentConfig())

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
            assert action.platform == "windows"

    @patch("remediation.windows_hardening._ps")
    def test_firewall_check_disabled(self, mock_ps):
        from remediation.windows_hardening import _WindowsHardening
        engine = _WindowsHardening()
        # PS returns count of disabled profiles; "2" means 2 profiles disabled
        mock_ps.return_value = (True, "2")

        needed, reason = engine._check_firewall()
        assert needed is True
        assert "disabled" in reason.lower() or "firewall" in reason.lower()

    @patch("remediation.windows_hardening._ps")
    def test_firewall_check_enabled(self, mock_ps):
        from remediation.windows_hardening import _WindowsHardening
        engine = _WindowsHardening()
        # PS returns "0" meaning 0 profiles disabled (all enabled)
        mock_ps.return_value = (True, "0")

        needed, reason = engine._check_firewall()
        assert needed is False

    @patch("remediation.windows_hardening._ps")
    def test_defender_check(self, mock_ps):
        from remediation.windows_hardening import _WindowsHardening
        engine = _WindowsHardening()
        # DisableRealtimeMonitoring = "True" means protection IS disabled
        mock_ps.return_value = (True, "True")

        needed, reason = engine._check_defender_realtime()
        assert needed is True

    @patch("remediation.windows_hardening._ps")
    def test_uac_check_low(self, mock_ps):
        from remediation.windows_hardening import _WindowsHardening
        engine = _WindowsHardening()
        mock_ps.return_value = (True, "0")  # UAC at lowest level

        needed, reason = engine._check_uac_max()
        assert needed is True

    @patch("remediation.windows_hardening._ps")
    def test_guest_account_enabled(self, mock_ps):
        from remediation.windows_hardening import _WindowsHardening
        engine = _WindowsHardening()
        mock_ps.return_value = (True, "True")  # Guest enabled

        needed, reason = engine._check_guest_account()
        assert needed is True
