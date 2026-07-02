"""
Sentinel Fleet — Policy Client

Pulls security profiles and policies from a central fleet server.
Policies can override local configuration for managed deployments.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any

from core.logging import get_logger
from core.config import AgentConfig, ScanConfig, ScanDepth


@dataclass
class FleetPolicy:
    """A security policy from the fleet server."""

    policy_id: str = ""
    name: str = ""
    description: str = ""
    profile: str = "standard"
    scan_depth: str = "standard"
    min_severity: str = "info"
    enabled_scanners: list[str] = field(default_factory=list)
    hardening_enabled: bool = False
    auto_remediate: bool = False
    scan_interval_minutes: int = 60
    force_compliance: bool = False
    custom_settings: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "profile": self.profile,
            "scan_depth": self.scan_depth,
            "min_severity": self.min_severity,
            "enabled_scanners": self.enabled_scanners,
            "hardening_enabled": self.hardening_enabled,
            "auto_remediate": self.auto_remediate,
            "scan_interval_minutes": self.scan_interval_minutes,
            "force_compliance": self.force_compliance,
            "custom_settings": self.custom_settings,
        }

    def apply_to_config(self, config: AgentConfig) -> AgentConfig:
        """Apply this policy to an AgentConfig, returning the modified config."""
        config.profile = self.profile
        config.scan.depth = ScanDepth(self.scan_depth)
        config.scan.min_severity = self.min_severity

        if self.auto_remediate:
            config.scan.auto_mode = True

        # Enable/disable specific scanners
        scanner_map = {
            "process": "enable_process_scan",
            "network": "enable_network_scan",
            "startup": "enable_startup_scan",
            "package": "enable_package_scan",
            "config": "enable_config_scan",
            "file_integrity": "enable_file_integrity_scan",
            "browser": "enable_browser_scan",
            "credential": "enable_credential_scan",
            "log_analysis": "enable_log_analysis_scan",
            "privilege": "enable_privilege_scan",
            "service_audit": "enable_service_audit_scan",
        }

        if self.enabled_scanners:
            # Disable all first, then enable specified ones
            for attr in scanner_map.values():
                setattr(config.scan, attr, False)
            for scanner_name in self.enabled_scanners:
                attr = scanner_map.get(scanner_name)
                if attr:
                    setattr(config.scan, attr, True)

        return config


@dataclass
class PolicyFetchResult:
    """Result of a policy fetch from the fleet server."""

    success: bool = False
    policy: FleetPolicy | None = None
    message: str = ""


class PolicyClient:
    """Fetches security policies from a fleet server."""

    def __init__(self, server_url: str, device_id: str, api_key: str = ""):
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.api_key = api_key
        self.log = get_logger()

    def fetch_policy(self) -> PolicyFetchResult:
        """Fetch the security policy assigned to this device."""
        if not self.server_url:
            return PolicyFetchResult(
                success=False,
                message="No fleet server URL configured",
            )

        try:
            url = f"{self.server_url}/api/v1/devices/{self.device_id}/policy"
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            req = urllib.request.Request(url, headers=headers, method="GET")

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            policy = FleetPolicy(
                policy_id=data.get("policy_id", ""),
                name=data.get("name", ""),
                description=data.get("description", ""),
                profile=data.get("profile", "standard"),
                scan_depth=data.get("scan_depth", "standard"),
                min_severity=data.get("min_severity", "info"),
                enabled_scanners=data.get("enabled_scanners", []),
                hardening_enabled=data.get("hardening_enabled", False),
                auto_remediate=data.get("auto_remediate", False),
                scan_interval_minutes=data.get("scan_interval_minutes", 60),
                force_compliance=data.get("force_compliance", False),
                custom_settings=data.get("custom_settings", {}),
            )

            self.log.info(f"Policy fetched: {policy.name} ({policy.policy_id})")

            return PolicyFetchResult(
                success=True,
                policy=policy,
                message=f"Policy '{policy.name}' fetched successfully",
            )

        except urllib.error.URLError as e:
            self.log.warning(f"Policy fetch failed: {e}")
            return PolicyFetchResult(
                success=False,
                message=f"Connection failed: {e}",
            )
        except Exception as e:
            self.log.error(f"Policy fetch error: {e}")
            return PolicyFetchResult(
                success=False,
                message=f"Policy fetch error: {e}",
            )
