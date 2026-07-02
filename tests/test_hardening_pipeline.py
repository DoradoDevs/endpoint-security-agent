"""Integration tests for the hardening pipeline: config -> engine -> actions."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig, Severity
from core.telemetry import Finding, ScanResult, SystemInfo


def _make_scan_result():
    return ScanResult(
        system_info=SystemInfo(
            hostname="test", os_name="Windows", os_version="10.0.22631",
            os_build="22631", architecture="AMD64", cpu_count=4,
            total_memory_gb=8.0, python_version="3.12", agent_version="2.0.0",
        ),
        findings=[
            Finding(title="Firewall disabled", description="test",
                    severity=Severity.CRITICAL, category="Network Security",
                    scanner="Test"),
        ],
        risk_score=50,
        risk_grade="C",
        scanners_run=["Test"],
        errors=[],
        scan_duration_seconds=1.0,
    )


class TestHardeningPipeline:

    @patch("remediation.hardening.platform.system", return_value="Windows")
    def test_dry_run_mode(self, _plat):
        from remediation.hardening import HardeningEngine, HardeningAction

        config = AgentConfig()
        config.scan.dry_run = True
        config.scan.auto_mode = True

        engine = HardeningEngine(config)
        # Replace with controlled mock actions
        engine.actions = [
            HardeningAction(
                name="Test Action",
                description="Test hardening",
                severity="high",
                check_fn=lambda: (True, "Needs fixing"),
                apply_fn=lambda: (True, "Fixed"),
                platform="windows",
            ),
        ]

        result = engine.apply(_make_scan_result())
        assert result["mode"] == "dry-run"
        assert len(result["applied"]) == 1
        assert result["applied"][0]["status"] == "dry-run"

    @patch("remediation.hardening.platform.system", return_value="Windows")
    def test_auto_mode_applies(self, _plat):
        from remediation.hardening import HardeningEngine, HardeningAction

        config = AgentConfig()
        config.scan.dry_run = False
        config.scan.auto_mode = True

        engine = HardeningEngine(config)
        engine.actions = [
            HardeningAction(
                name="Enable Something",
                description="Enable a setting",
                severity="high",
                check_fn=lambda: (True, "Disabled"),
                apply_fn=lambda: (True, "Enabled"),
                platform="windows",
            ),
        ]

        result = engine.apply(_make_scan_result())
        assert result["mode"] == "live"
        assert result["applied"][0]["status"] == "applied"

    @patch("remediation.hardening.platform.system", return_value="Windows")
    def test_manual_mode_pending(self, _plat):
        from remediation.hardening import HardeningEngine, HardeningAction

        config = AgentConfig()
        config.scan.dry_run = False
        config.scan.auto_mode = False

        engine = HardeningEngine(config)
        engine.actions = [
            HardeningAction(
                name="Risky Action",
                description="Needs confirmation",
                severity="high",
                check_fn=lambda: (True, "Not configured"),
                apply_fn=lambda: (True, "Done"),
                platform="windows",
            ),
        ]

        result = engine.apply(_make_scan_result())
        assert result["applied"][0]["status"] == "pending_confirmation"

    @patch("remediation.hardening.platform.system", return_value="Windows")
    def test_already_compliant_skipped(self, _plat):
        from remediation.hardening import HardeningEngine, HardeningAction

        config = AgentConfig()
        config.scan.auto_mode = True

        engine = HardeningEngine(config)
        engine.actions = [
            HardeningAction(
                name="Already Good",
                description="Already configured",
                severity="medium",
                check_fn=lambda: (False, "Already compliant"),
                apply_fn=lambda: (True, "Done"),
                platform="windows",
            ),
        ]

        result = engine.apply(_make_scan_result())
        assert len(result["skipped"]) == 1
        assert len(result["applied"]) == 0

    @patch("remediation.hardening.platform.system", return_value="Windows")
    def test_action_failure_logged(self, _plat):
        from remediation.hardening import HardeningEngine, HardeningAction

        config = AgentConfig()
        config.scan.auto_mode = True

        engine = HardeningEngine(config)
        engine.actions = [
            HardeningAction(
                name="Failing Action",
                description="Will fail",
                severity="high",
                check_fn=lambda: (True, "Needs fix"),
                apply_fn=lambda: (False, "Access denied"),
                platform="windows",
            ),
        ]

        result = engine.apply(_make_scan_result())
        assert len(result["errors"]) == 1
