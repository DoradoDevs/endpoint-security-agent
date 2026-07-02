"""Shared pytest fixtures for Sentinel Agent test suite."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.config import AgentConfig, ScanConfig, ScanDepth, Severity
from core.telemetry import Finding, ScanResult, SystemInfo


@pytest.fixture
def default_config() -> AgentConfig:
    """Standard AgentConfig for testing."""
    return AgentConfig()


@pytest.fixture
def deep_config() -> AgentConfig:
    """AgentConfig with deep scan enabled."""
    config = AgentConfig()
    config.scan.depth = ScanDepth.DEEP
    return config


@pytest.fixture
def sample_system_info() -> SystemInfo:
    """Sample system info for testing."""
    return SystemInfo(
        hostname="test-machine",
        os_name="Windows",
        os_version="10.0.22631",
        os_build="22631",
        architecture="AMD64",
        cpu_count=8,
        total_memory_gb=16.0,
        python_version="3.12.0",
        agent_version="2.0.0",
    )


def make_finding(
    title: str = "Test Finding",
    severity: str = "medium",
    category: str = "Test",
    scanner: str = "TestScanner",
    description: str = "Test description",
    remediation: str = "Fix it",
    **kwargs,
) -> Finding:
    """Factory for creating test Findings."""
    return Finding(
        title=title,
        description=description,
        severity=Severity(severity),
        category=category,
        scanner=scanner,
        remediation=remediation,
        **kwargs,
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Sample findings covering all severities."""
    return [
        make_finding("Critical Issue", severity="critical", category="Malware Indicators"),
        make_finding("High Risk", severity="high", category="Network Security"),
        make_finding("Medium Concern", severity="medium", category="System Configuration"),
        make_finding("Low Priority", severity="low", category="Access Control"),
        make_finding("Info Note", severity="info", category="Inventory"),
    ]


@pytest.fixture
def sample_scan_result(sample_system_info, sample_findings) -> ScanResult:
    """Sample ScanResult for testing."""
    return ScanResult(
        system_info=sample_system_info,
        findings=sample_findings,
        risk_score=45,
        risk_grade="C",
        scanners_run=["ProcessScanner", "NetworkScanner", "ConfigScanner"],
        errors=[],
        scan_duration_seconds=3.5,
    )


@pytest.fixture
def mock_os_module():
    """Mock OS module with sensible defaults."""
    from os_modules.base import (
        FirewallStatus, EncryptionStatus, UpdateStatus,
        SecureBootStatus, StartupEntry, ServiceInfo,
    )

    module = MagicMock()
    module.platform_name = "windows"
    module.get_firewall_status.return_value = FirewallStatus(
        enabled=True, details="All profiles enabled", rules_count=50,
    )
    module.get_encryption_status.return_value = EncryptionStatus(
        enabled=True, method="BitLocker", details="C: fully encrypted",
    )
    module.get_update_status.return_value = UpdateStatus(
        auto_updates_enabled=True, pending_updates=0, last_check="2024-01-01",
        details="Up to date",
    )
    module.get_secure_boot_status.return_value = SecureBootStatus(
        supported=True, enabled=True, details="Secure Boot active",
    )
    module.get_startup_entries.return_value = [
        StartupEntry(name="Defender", command="C:\\Windows\\Defender\\MSASCuiL.exe",
                     location="HKLM\\Run", enabled=True),
    ]
    module.get_running_services.return_value = [
        ServiceInfo(name="wuauserv", display_name="Windows Update",
                    status="running", start_type="automatic", pid=1234),
    ]
    module.get_admin_users.return_value = ["Administrator"]
    module.get_password_policy.return_value = {"Minimum password length": "8"}
    module.get_os_patch_level.return_value = {"version": "10.0.22631"}
    return module
