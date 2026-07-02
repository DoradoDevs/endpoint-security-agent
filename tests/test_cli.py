"""Tests for cli.main — CLI argument parsing and workflows."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from cli.main import parse_args, _severity_style


class TestParseArgs:

    def test_scan_flag(self):
        args = parse_args(["--scan"])
        assert args.scan is True

    def test_deep_scan_flag(self):
        args = parse_args(["--deep-scan"])
        assert args.deep_scan is True

    def test_harden_flags(self):
        args = parse_args(["--harden", "--dry-run", "--auto"])
        assert args.harden is True
        assert args.dry_run is True
        assert args.auto is True

    def test_report_flag(self):
        args = parse_args(["--scan", "--report"])
        assert args.scan is True
        assert args.report is True

    def test_profile_flag(self):
        args = parse_args(["--profile", "strict", "--scan"])
        assert args.profile == "strict"

    def test_list_profiles(self):
        args = parse_args(["--list-profiles"])
        assert args.list_profiles is True

    def test_show_profile(self):
        args = parse_args(["--show-profile", "fort_knox"])
        assert args.show_profile == "fort_knox"

    def test_daemon_flag(self):
        args = parse_args(["--daemon"])
        assert args.daemon is True

    def test_stop_daemon_flag(self):
        args = parse_args(["--stop-daemon"])
        assert args.stop_daemon is True

    def test_daemon_status_flag(self):
        args = parse_args(["--daemon-status"])
        assert args.daemon_status is True

    def test_no_args_shows_help(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_server_mode(self):
        args = parse_args(["--scan", "--server-mode"])
        assert args.server_mode is True

    def test_output_dir(self):
        args = parse_args(["--scan", "--report", "--output-dir", "/tmp/reports"])
        assert args.output_dir == "/tmp/reports"

    def test_update_flag(self):
        args = parse_args(["--update"])
        assert args.update is True

    def test_combined_scan_harden_report(self):
        args = parse_args(["--scan", "--harden", "--report", "--auto"])
        assert args.scan is True
        assert args.harden is True
        assert args.report is True
        assert args.auto is True


class TestSeverityStyle:

    def test_critical_style(self):
        assert "red" in _severity_style("critical")

    def test_high_style(self):
        assert "yellow" in _severity_style("high")

    def test_info_style(self):
        assert "dim" in _severity_style("info")

    def test_unknown_style(self):
        assert _severity_style("unknown") == "white"


class TestMainWorkflows:

    @patch("cli.main.console")
    def test_list_profiles_workflow(self, mock_console):
        from cli.main import main
        result = main(["--list-profiles"])
        assert result == 0

    @patch("cli.main.console")
    def test_show_profile_workflow(self, mock_console):
        from cli.main import main
        result = main(["--show-profile", "standard"])
        assert result == 0

    @patch("core.daemon.SentinelDaemon.is_running", return_value=False)
    @patch("cli.main.console")
    def test_daemon_status_not_running(self, mock_console, mock_is_running):
        from cli.main import main
        result = main(["--daemon-status"])
        assert result == 0

    @patch("core.daemon.SentinelDaemon.stop_running", return_value=False)
    @patch("cli.main.console")
    def test_stop_daemon_none_running(self, mock_console, mock_stop):
        from cli.main import main
        result = main(["--stop-daemon"])
        assert result == 0
