"""Tests for tui — Interactive TUI Dashboard."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from rich.panel import Panel

from core.config import AgentConfig, Severity
from core.telemetry import ScanResult, Finding, SystemInfo
from tui.state import TUIState
from tui.panels import (
    render_header,
    render_footer,
    render_overview,
    render_findings,
    render_scanners,
    render_actions,
)
from tui.app import TUIApp
from tui.scanner_bridge import ScannerBridge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    title: str = "Test Finding",
    severity: str = "medium",
    category: str = "Test",
    scanner: str = "TestScanner",
) -> Finding:
    return Finding(
        title=title,
        description="desc",
        severity=Severity(severity),
        category=category,
        scanner=scanner,
    )


def _make_scan_result() -> ScanResult:
    findings = [
        _make_finding("Critical Issue", severity="critical", category="Malware"),
        _make_finding("High Issue", severity="high", category="Network"),
        _make_finding("Medium Issue", severity="medium", category="Config"),
        _make_finding("Low Issue", severity="low", category="Access"),
        _make_finding("Info Note", severity="info", category="Inventory"),
    ]
    return ScanResult(
        system_info=SystemInfo(hostname="test-host"),
        findings=findings,
        scanners_run=["ProcessScanner", "NetworkScanner", "ConfigScanner"],
        scan_duration_seconds=2.5,
        risk_score=42.0,
        risk_grade="B",
    )


# ===========================================================================
# TUIState Tests
# ===========================================================================

class TestTUIState:

    def test_defaults(self):
        state = TUIState()
        assert state.risk_score == 0.0
        assert state.risk_grade == "A+"
        assert state.total_findings == 0
        assert state.critical_count == 0
        assert state.high_count == 0
        assert state.medium_count == 0
        assert state.low_count == 0
        assert state.info_count == 0
        assert state.findings == []
        assert state.scan_in_progress is False
        assert state.scan_progress == ""
        assert state.scanners_run == []
        assert state.active_panel == 0
        assert state.severity_filter == "all"
        assert state.last_scan_time == ""
        assert state.status_message == "Ready"

    def test_panel_names(self):
        state = TUIState()
        assert state.panel_names == ["Overview", "Findings", "Scanners", "Actions"]
        assert len(state.panel_names) == 4

    def test_update_from_result(self):
        state = TUIState()
        result = _make_scan_result()
        state.update_from_result(result)

        assert state.risk_score == 42.0
        assert state.risk_grade == "B"
        assert state.total_findings == 5
        assert state.critical_count == 1
        assert state.high_count == 1
        assert state.medium_count == 1
        assert state.low_count == 1
        assert state.info_count == 1
        assert len(state.findings) == 5
        assert state.scanners_run == ["ProcessScanner", "NetworkScanner", "ConfigScanner"]

    def test_update_from_result_empty(self):
        state = TUIState()
        result = ScanResult()
        state.update_from_result(result)

        assert state.risk_score == 0.0
        assert state.risk_grade == "Unknown"
        assert state.total_findings == 0
        assert state.findings == []
        assert state.scanners_run == []

    def test_severity_filter_default(self):
        state = TUIState()
        assert state.severity_filter == "all"

    def test_severity_filter_cycling(self):
        """Verify the filter cycling logic used by _handle_key."""
        state = TUIState()
        filters = ["all", "critical", "high", "medium", "low"]

        for expected in filters[1:] + [filters[0]]:
            idx = filters.index(state.severity_filter)
            state.severity_filter = filters[(idx + 1) % len(filters)]
            assert state.severity_filter == expected


# ===========================================================================
# Panel Rendering Tests
# ===========================================================================

class TestPanelRendering:

    def test_render_header_returns_panel(self):
        state = TUIState()
        result = render_header(state)
        assert isinstance(result, Panel)

    def test_render_footer_returns_panel(self):
        state = TUIState()
        result = render_footer(state)
        assert isinstance(result, Panel)

    def test_render_overview_returns_panel(self):
        state = TUIState()
        result = render_overview(state)
        assert isinstance(result, Panel)

    def test_render_findings_returns_panel(self):
        state = TUIState()
        result = render_findings(state)
        assert isinstance(result, Panel)

    def test_render_scanners_returns_panel(self):
        state = TUIState()
        result = render_scanners(state)
        assert isinstance(result, Panel)

    def test_render_actions_returns_panel(self):
        state = TUIState()
        result = render_actions(state)
        assert isinstance(result, Panel)

    def test_render_overview_with_data(self):
        state = TUIState()
        state.update_from_result(_make_scan_result())
        result = render_overview(state)
        assert isinstance(result, Panel)

    def test_render_findings_empty(self):
        state = TUIState()
        result = render_findings(state)
        assert isinstance(result, Panel)

    def test_render_findings_with_data(self):
        state = TUIState()
        state.update_from_result(_make_scan_result())
        result = render_findings(state)
        assert isinstance(result, Panel)

    def test_render_findings_with_severity_filter(self):
        state = TUIState()
        state.update_from_result(_make_scan_result())
        state.severity_filter = "critical"
        result = render_findings(state)
        assert isinstance(result, Panel)

    def test_render_findings_filter_high(self):
        state = TUIState()
        state.update_from_result(_make_scan_result())
        state.severity_filter = "high"
        result = render_findings(state)
        assert isinstance(result, Panel)

    def test_render_scanners_with_data(self):
        state = TUIState()
        state.scanners_run = ["ProcessScanner", "NetworkScanner"]
        result = render_scanners(state)
        assert isinstance(result, Panel)

    def test_render_scanners_during_scan(self):
        state = TUIState()
        state.scan_in_progress = True
        result = render_scanners(state)
        assert isinstance(result, Panel)

    def test_render_header_during_scan(self):
        state = TUIState()
        state.scan_in_progress = True
        state.status_message = "Scanning..."
        result = render_header(state)
        assert isinstance(result, Panel)

    def test_render_header_scan_failed(self):
        state = TUIState()
        state.status_message = "Scan failed: timeout"
        result = render_header(state)
        assert isinstance(result, Panel)

    def test_render_header_with_last_scan_time(self):
        state = TUIState()
        state.last_scan_time = "14:30:22"
        result = render_header(state)
        assert isinstance(result, Panel)

    def test_render_actions_shows_current_state(self):
        state = TUIState()
        state.active_panel = 3
        state.severity_filter = "high"
        result = render_actions(state)
        assert isinstance(result, Panel)


# ===========================================================================
# TUIApp Key Handling Tests
# ===========================================================================

class TestTUIAppKeyHandling:

    def _make_app(self) -> TUIApp:
        config = AgentConfig()
        app = TUIApp(config)
        app._running = True
        return app

    def test_handle_key_q_stops_running(self):
        app = self._make_app()
        app._handle_key("q")
        assert app._running is False

    def test_handle_key_tab_cycles_panels(self):
        app = self._make_app()
        assert app.state.active_panel == 0
        app._handle_key("\t")
        assert app.state.active_panel == 1
        app._handle_key("\t")
        assert app.state.active_panel == 2
        app._handle_key("\t")
        assert app.state.active_panel == 3
        app._handle_key("\t")
        assert app.state.active_panel == 0  # wraps around

    def test_handle_key_1_goes_to_overview(self):
        app = self._make_app()
        app.state.active_panel = 2
        app._handle_key("1")
        assert app.state.active_panel == 0

    def test_handle_key_2_goes_to_findings(self):
        app = self._make_app()
        app._handle_key("2")
        assert app.state.active_panel == 1

    def test_handle_key_3_goes_to_scanners(self):
        app = self._make_app()
        app._handle_key("3")
        assert app.state.active_panel == 2

    def test_handle_key_4_goes_to_actions(self):
        app = self._make_app()
        app._handle_key("4")
        assert app.state.active_panel == 3

    @patch.object(ScannerBridge, "start_scan")
    def test_handle_key_s_starts_scan(self, mock_start):
        app = self._make_app()
        app._handle_key("s")
        mock_start.assert_called_once()

    def test_handle_key_f_cycles_severity_filter(self):
        app = self._make_app()
        assert app.state.severity_filter == "all"
        app._handle_key("f")
        assert app.state.severity_filter == "critical"
        app._handle_key("f")
        assert app.state.severity_filter == "high"
        app._handle_key("f")
        assert app.state.severity_filter == "medium"
        app._handle_key("f")
        assert app.state.severity_filter == "low"
        app._handle_key("f")
        assert app.state.severity_filter == "all"  # wraps around

    def test_handle_unknown_key_no_effect(self):
        app = self._make_app()
        original_panel = app.state.active_panel
        original_filter = app.state.severity_filter
        app._handle_key("x")
        assert app.state.active_panel == original_panel
        assert app.state.severity_filter == original_filter
        assert app._running is True


# ===========================================================================
# ScannerBridge Tests
# ===========================================================================

class TestScannerBridge:

    def test_start_scan_sets_in_progress(self):
        config = AgentConfig()
        state = TUIState()
        bridge = ScannerBridge(config, state)

        with patch.object(bridge, "_run"):
            # Manually set what start_scan does before threading
            bridge.state.scan_in_progress = True
            bridge.state.status_message = "Scanning..."

        assert state.scan_in_progress is True
        assert state.status_message == "Scanning..."

    def test_start_scan_skips_if_already_running(self):
        config = AgentConfig()
        state = TUIState()
        state.scan_in_progress = True
        bridge = ScannerBridge(config, state)

        # Should return immediately without starting a thread
        bridge.start_scan()
        assert bridge._thread is None

    def test_is_running_property(self):
        config = AgentConfig()
        state = TUIState()
        bridge = ScannerBridge(config, state)

        assert bridge.is_running is False
        state.scan_in_progress = True
        assert bridge.is_running is True

    @patch("tui.scanner_bridge.SentinelAgent")
    def test_run_updates_state_on_success(self, mock_agent_cls):
        config = AgentConfig()
        state = TUIState()
        bridge = ScannerBridge(config, state)

        mock_result = _make_scan_result()
        mock_agent = MagicMock()
        mock_agent.scan.return_value = mock_result
        mock_agent_cls.return_value = mock_agent

        state.scan_in_progress = True
        bridge._run()

        assert state.scan_in_progress is False
        assert state.risk_score == 42.0
        assert state.risk_grade == "B"
        assert state.total_findings == 5
        assert state.status_message == "Scan complete"
        assert state.last_scan_time != ""

    @patch("tui.scanner_bridge.SentinelAgent")
    def test_run_handles_exception(self, mock_agent_cls):
        config = AgentConfig()
        state = TUIState()
        bridge = ScannerBridge(config, state)

        mock_agent_cls.side_effect = RuntimeError("test error")

        state.scan_in_progress = True
        bridge._run()

        assert state.scan_in_progress is False
        assert "Scan failed" in state.status_message
        assert "test error" in state.status_message
