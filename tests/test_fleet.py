"""Tests for fleet management — registration, telemetry, policy."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.config import AgentConfig, FleetConfig


class TestAgentRegistration:

    @patch("fleet.agent_registration.platform")
    def test_generate_device_id(self, mock_plat):
        from fleet.agent_registration import _generate_device_id
        mock_plat.node.return_value = "test-host"
        mock_plat.machine.return_value = "AMD64"
        mock_plat.system.return_value = "Windows"

        device_id = _generate_device_id()
        assert isinstance(device_id, str)
        assert len(device_id) == 16

    @patch("fleet.agent_registration.platform")
    def test_device_id_is_stable(self, mock_plat):
        from fleet.agent_registration import _generate_device_id
        mock_plat.node.return_value = "test-host"
        mock_plat.machine.return_value = "AMD64"
        mock_plat.system.return_value = "Windows"

        id1 = _generate_device_id()
        id2 = _generate_device_id()
        assert id1 == id2

    def test_create_identity(self):
        from fleet.agent_registration import AgentRegistration
        reg = AgentRegistration()
        identity = reg.create_identity(agent_version="2.0.0")

        assert identity.device_id
        assert identity.agent_version == "2.0.0"
        assert identity.enrolled_at

    def test_save_and_load_identity(self):
        from fleet.agent_registration import AgentRegistration, DeviceIdentity
        with tempfile.TemporaryDirectory() as tmpdir:
            reg = AgentRegistration()
            reg._data_dir = Path(tmpdir)
            reg._identity_file = Path(tmpdir) / "device_identity.json"

            identity = DeviceIdentity(
                device_id="test123",
                hostname="test-host",
                os_name="Windows",
                agent_version="2.0.0",
                enrolled_at="2024-01-01T00:00:00Z",
            )

            reg.save_identity(identity)
            loaded = reg.load_identity()

            assert loaded is not None
            assert loaded.device_id == "test123"
            assert loaded.hostname == "test-host"

    def test_enroll_no_server_url(self):
        from fleet.agent_registration import AgentRegistration
        reg = AgentRegistration(server_url="", enrollment_token="tok")
        result = reg.enroll()
        assert result.success is False
        assert "No fleet server" in result.message

    def test_enroll_no_token(self):
        from fleet.agent_registration import AgentRegistration
        reg = AgentRegistration(server_url="https://fleet.example.com", enrollment_token="")
        result = reg.enroll()
        assert result.success is False
        assert "No enrollment token" in result.message

    def test_is_enrolled_false_initially(self):
        from fleet.agent_registration import AgentRegistration
        with tempfile.TemporaryDirectory() as tmpdir:
            reg = AgentRegistration()
            reg._data_dir = Path(tmpdir)
            reg._identity_file = Path(tmpdir) / "device_identity.json"
            assert reg.is_enrolled() is False


class TestTelemetryClient:

    def test_build_payload(self):
        from fleet.telemetry_client import TelemetryClient
        from core.telemetry import ScanResult, SystemInfo, Finding
        from core.config import Severity

        client = TelemetryClient(
            server_url="https://fleet.example.com",
            device_id="dev123",
            enabled=True,
        )

        result = ScanResult(
            system_info=SystemInfo(
                hostname="test", os_name="Windows",
                os_version="10.0", agent_version="2.0.0",
            ),
            findings=[
                Finding(title="Test", description="desc",
                        severity=Severity.HIGH, category="Test", scanner="Test"),
            ],
            risk_score=35.0,
            risk_grade="B",
            scanners_run=["TestScanner"],
            errors=[],
            scan_duration_seconds=1.0,
        )

        payload = client.build_payload(result)
        assert payload.device_id == "dev123"
        assert payload.risk_score == 35.0
        assert payload.findings_count == 1
        assert payload.findings_by_severity.get("high") == 1

    def test_submit_not_enabled(self):
        from fleet.telemetry_client import TelemetryClient
        from core.telemetry import ScanResult, SystemInfo

        client = TelemetryClient(
            server_url="https://fleet.example.com",
            device_id="dev123",
            enabled=False,
        )

        result = ScanResult(
            system_info=SystemInfo(),
            findings=[], risk_score=0, risk_grade="A+",
            scanners_run=[], errors=[], scan_duration_seconds=0,
        )

        response = client.submit(result)
        assert response.success is False
        assert "not enabled" in response.message

    def test_submit_no_server_url(self):
        from fleet.telemetry_client import TelemetryClient
        from core.telemetry import ScanResult, SystemInfo

        client = TelemetryClient(
            server_url="",
            device_id="dev123",
            enabled=True,
        )

        result = ScanResult(
            system_info=SystemInfo(),
            findings=[], risk_score=0, risk_grade="A+",
            scanners_run=[], errors=[], scan_duration_seconds=0,
        )

        response = client.submit(result)
        assert response.success is False


class TestPolicyClient:

    def test_fetch_no_server_url(self):
        from fleet.policy_client import PolicyClient
        client = PolicyClient(server_url="", device_id="dev123")
        result = client.fetch_policy()
        assert result.success is False
        assert "No fleet server" in result.message

    def test_fleet_policy_apply_to_config(self):
        from fleet.policy_client import FleetPolicy
        policy = FleetPolicy(
            policy_id="pol1",
            name="Strict Policy",
            profile="strict",
            scan_depth="deep",
            min_severity="high",
            enabled_scanners=["process", "network", "credential"],
            auto_remediate=True,
        )

        config = AgentConfig()
        config = policy.apply_to_config(config)

        assert config.profile == "strict"
        assert config.scan.depth.value == "deep"
        assert config.scan.min_severity == "high"
        assert config.scan.auto_mode is True
        assert config.scan.enable_process_scan is True
        assert config.scan.enable_network_scan is True
        assert config.scan.enable_credential_scan is True
        assert config.scan.enable_startup_scan is False  # Not in enabled_scanners

    def test_fleet_policy_empty_scanners_no_change(self):
        from fleet.policy_client import FleetPolicy
        policy = FleetPolicy(
            policy_id="pol1",
            name="Default",
            enabled_scanners=[],  # Empty means don't override
        )

        config = AgentConfig()
        original_process = config.scan.enable_process_scan
        config = policy.apply_to_config(config)
        assert config.scan.enable_process_scan == original_process


class TestFleetConfig:

    def test_default_fleet_config(self):
        config = AgentConfig()
        assert config.fleet.enabled is False
        assert config.fleet.server_url == ""
        assert config.fleet.telemetry_opt_in is False

    def test_fleet_config_serialization(self):
        config = AgentConfig()
        config.fleet.enabled = True
        config.fleet.server_url = "https://fleet.example.com"
        config.fleet.telemetry_opt_in = True

        data = config.to_dict()
        assert data["fleet"]["enabled"] is True
        assert data["fleet"]["server_url"] == "https://fleet.example.com"
