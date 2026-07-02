"""
Sentinel Agent — Security Profiles

Predefined and custom security profiles that control scanning depth,
enabled scanners, hardening behavior, and severity thresholds.

Profiles:
  minimal     — Light scan, no auto-remediation. For developers who need flexibility.
  standard    — Balanced scanning and reporting. Recommended for most desktop users.
  strict      — Deep scanning, aggressive flagging. For security-conscious users.
  fort_knox   — Maximum security. CIS-aligned hardening, all checks, auto-remediation.
  custom      — User-defined profile loaded from JSON configuration file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any

from core.config import ScanDepth, Severity, ScanConfig


class SecurityProfile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    FORT_KNOX = "fort_knox"
    CUSTOM = "custom"


@dataclass
class ProfileSpec:
    """Complete specification of what a security profile enables."""

    name: str
    description: str
    scan_depth: ScanDepth

    # Scanner toggles — existing scanners
    enable_process_scan: bool = True
    enable_network_scan: bool = True
    enable_startup_scan: bool = True
    enable_package_scan: bool = True
    enable_config_scan: bool = True
    enable_cve_lookup: bool = True

    # Scanner toggles — new scanners (Phase 2)
    enable_file_integrity_scan: bool = False
    enable_browser_scan: bool = False
    enable_credential_scan: bool = False
    enable_log_analysis_scan: bool = False
    enable_privilege_scan: bool = False
    enable_service_audit_scan: bool = False

    # v3.0 features
    enable_threat_intel: bool = False
    enable_network_vuln_scan: bool = False
    enable_device_scan: bool = False
    enable_cloud_scan: bool = False
    # v3.5 threat hunting
    enable_malware_scan: bool = False
    enable_memory_scan: bool = False
    enable_persistence_scan: bool = False
    enable_heuristic_scan: bool = False
    enable_ioc_scan: bool = False
    response_level: str = "log_and_alert"  # alert_only, log_and_alert, prompt, auto_respond

    # Severity threshold — only report findings at this level or above
    min_severity: Severity = Severity.INFO

    # Hardening behavior
    enable_hardening: bool = False
    auto_remediate: bool = False
    hardening_actions_enabled: list[str] = field(default_factory=list)

    # Monitoring (Phase 4)
    enable_continuous_monitoring: bool = False
    scan_interval_minutes: int = 0

    def to_scan_config(self) -> ScanConfig:
        """Convert profile to a ScanConfig for backward compatibility."""
        return ScanConfig(
            depth=self.scan_depth,
            enable_process_scan=self.enable_process_scan,
            enable_network_scan=self.enable_network_scan,
            enable_startup_scan=self.enable_startup_scan,
            enable_package_scan=self.enable_package_scan,
            enable_config_scan=self.enable_config_scan,
            enable_cve_lookup=self.enable_cve_lookup,
            enable_file_integrity_scan=self.enable_file_integrity_scan,
            enable_browser_scan=self.enable_browser_scan,
            enable_credential_scan=self.enable_credential_scan,
            enable_log_analysis_scan=self.enable_log_analysis_scan,
            enable_privilege_scan=self.enable_privilege_scan,
            enable_service_audit_scan=self.enable_service_audit_scan,
            enable_threat_intel=self.enable_threat_intel,
            enable_network_vuln_scan=self.enable_network_vuln_scan,
            enable_device_scan=self.enable_device_scan,
            enable_cloud_scan=self.enable_cloud_scan,
            enable_malware_scan=self.enable_malware_scan,
            enable_memory_scan=self.enable_memory_scan,
            enable_persistence_scan=self.enable_persistence_scan,
            enable_heuristic_scan=self.enable_heuristic_scan,
            enable_ioc_scan=self.enable_ioc_scan,
            min_severity=self.min_severity.value,
            auto_mode=self.auto_remediate,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile to a dictionary."""
        data = asdict(self)
        data["scan_depth"] = self.scan_depth.value
        data["min_severity"] = self.min_severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProfileSpec:
        """Deserialize profile from a dictionary."""
        if "scan_depth" in data:
            data["scan_depth"] = ScanDepth(data["scan_depth"])
        if "min_severity" in data:
            data["min_severity"] = Severity(data["min_severity"])
        return cls(**data)


# ===== Built-in profile definitions =====

BUILTIN_PROFILES: dict[SecurityProfile, ProfileSpec] = {
    SecurityProfile.MINIMAL: ProfileSpec(
        name="Minimal",
        description="Light scan, no auto-remediation. For developers who need flexibility.",
        scan_depth=ScanDepth.QUICK,
        enable_process_scan=True,
        enable_network_scan=True,
        enable_startup_scan=False,
        enable_package_scan=False,
        enable_config_scan=True,
        enable_cve_lookup=False,
        min_severity=Severity.HIGH,
        enable_hardening=False,
        response_level="alert_only",
    ),
    SecurityProfile.STANDARD: ProfileSpec(
        name="Standard",
        description="Balanced scanning and reporting. Recommended for most desktop users.",
        scan_depth=ScanDepth.STANDARD,
        enable_process_scan=True,
        enable_network_scan=True,
        enable_startup_scan=True,
        enable_package_scan=True,
        enable_config_scan=True,
        enable_cve_lookup=True,
        min_severity=Severity.LOW,
        enable_hardening=False,
    ),
    SecurityProfile.STRICT: ProfileSpec(
        name="Strict",
        description="Deep scanning, aggressive flagging. For security-conscious users.",
        scan_depth=ScanDepth.DEEP,
        enable_process_scan=True,
        enable_network_scan=True,
        enable_startup_scan=True,
        enable_package_scan=True,
        enable_config_scan=True,
        enable_cve_lookup=True,
        enable_file_integrity_scan=True,
        enable_credential_scan=True,
        enable_privilege_scan=True,
        enable_service_audit_scan=True,
        enable_threat_intel=True,
        enable_network_vuln_scan=True,
        enable_device_scan=True,
        enable_cloud_scan=True,
        enable_malware_scan=True,
        enable_persistence_scan=True,
        enable_ioc_scan=True,
        response_level="prompt",
        min_severity=Severity.INFO,
        enable_hardening=True,
        auto_remediate=False,
    ),
    SecurityProfile.FORT_KNOX: ProfileSpec(
        name="Fort Knox",
        description="Maximum security. CIS-aligned hardening, all checks, auto-remediation.",
        scan_depth=ScanDepth.DEEP,
        enable_process_scan=True,
        enable_network_scan=True,
        enable_startup_scan=True,
        enable_package_scan=True,
        enable_config_scan=True,
        enable_cve_lookup=True,
        enable_file_integrity_scan=True,
        enable_browser_scan=True,
        enable_credential_scan=True,
        enable_log_analysis_scan=True,
        enable_privilege_scan=True,
        enable_service_audit_scan=True,
        enable_threat_intel=True,
        enable_network_vuln_scan=True,
        enable_device_scan=True,
        enable_cloud_scan=True,
        enable_malware_scan=True,
        enable_memory_scan=True,
        enable_persistence_scan=True,
        enable_heuristic_scan=True,
        enable_ioc_scan=True,
        response_level="auto_respond",
        min_severity=Severity.INFO,
        enable_hardening=True,
        auto_remediate=True,
        enable_continuous_monitoring=True,
        scan_interval_minutes=60,
    ),
}


def load_custom_profile(path: Path) -> ProfileSpec:
    """Load a user-defined custom profile from a JSON file."""
    data = json.loads(path.read_text())
    return ProfileSpec.from_dict(data)


def save_custom_profile(spec: ProfileSpec, path: Path) -> None:
    """Save a custom profile to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec.to_dict(), indent=2))


def get_profile(profile: SecurityProfile, custom_path: Path | None = None) -> ProfileSpec:
    """Get a profile spec by name, with optional custom override."""
    if profile == SecurityProfile.CUSTOM:
        if custom_path is None:
            raise ValueError("Custom profile requires a --profile-config path")
        return load_custom_profile(custom_path)
    return BUILTIN_PROFILES[profile]


def list_profiles() -> list[dict[str, str]]:
    """Return summary info for all built-in profiles."""
    summaries = []
    for profile_enum, spec in BUILTIN_PROFILES.items():
        scanner_count = sum(1 for attr in [
            spec.enable_process_scan, spec.enable_network_scan,
            spec.enable_startup_scan, spec.enable_package_scan,
            spec.enable_config_scan, spec.enable_file_integrity_scan,
            spec.enable_browser_scan, spec.enable_credential_scan,
            spec.enable_log_analysis_scan, spec.enable_privilege_scan,
            spec.enable_service_audit_scan, spec.enable_threat_intel,
            spec.enable_network_vuln_scan,
            spec.enable_device_scan,
            spec.enable_cloud_scan,
            spec.enable_malware_scan,
            spec.enable_memory_scan,
            spec.enable_persistence_scan,
            spec.enable_heuristic_scan,
            spec.enable_ioc_scan,
        ] if attr)
        summaries.append({
            "id": profile_enum.value,
            "name": spec.name,
            "description": spec.description,
            "depth": spec.scan_depth.value,
            "scanners": str(scanner_count),
            "hardening": "Yes" if spec.enable_hardening else "No",
            "auto_remediate": "Yes" if spec.auto_remediate else "No",
            "min_severity": spec.min_severity.value,
        })
    return summaries
