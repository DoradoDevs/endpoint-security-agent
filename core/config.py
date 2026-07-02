"""
Sentinel Agent — Configuration Management

Centralized configuration with safe defaults. All config is explicit,
auditable, and never modifies host state on its own.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class ScanDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class AgentEdition(str, Enum):
    DESKTOP = "desktop"
    SERVER = "server"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.0,
        }[self]


@dataclass
class ScanConfig:
    depth: ScanDepth = ScanDepth.STANDARD
    enable_network_scan: bool = True
    enable_process_scan: bool = True
    enable_startup_scan: bool = True
    enable_package_scan: bool = True
    enable_config_scan: bool = True
    enable_cve_lookup: bool = True
    # New scanners (v2.0)
    enable_file_integrity_scan: bool = False
    enable_browser_scan: bool = False
    enable_credential_scan: bool = False
    enable_log_analysis_scan: bool = False
    enable_privilege_scan: bool = False
    enable_service_audit_scan: bool = False
    # v3.0 scanners
    enable_threat_intel: bool = False
    enable_network_vuln_scan: bool = False
    enable_device_scan: bool = False
    enable_cloud_scan: bool = False
    # v3.5 threat hunting scanners
    enable_malware_scan: bool = False
    enable_memory_scan: bool = False
    enable_persistence_scan: bool = False
    enable_heuristic_scan: bool = False
    enable_ioc_scan: bool = False
    enable_yara_scan: bool = False
    enable_amsi_scan: bool = False
    network_scan_targets: list = field(default_factory=list)
    # Severity filter — drop findings below this level
    min_severity: str = "info"
    dry_run: bool = False
    auto_mode: bool = False
    server_mode: bool = False


@dataclass
class ReportConfig:
    output_dir: Path = field(default_factory=lambda: Path.cwd() / "sentinel_reports")
    generate_html: bool = True
    generate_json: bool = True
    include_summary: bool = True


@dataclass
class ThreatIntelConfig:
    enabled: bool = False
    refresh_on_scan: bool = True
    otx_api_key: str = ""
    custom_ioc_file: str = ""
    feed_refresh_hours: int = 6


@dataclass
class ResponseConfig:
    enabled: bool = False
    auto_respond: bool = False
    enable_process_kill: bool = True
    enable_file_quarantine: bool = True
    enable_network_block: bool = True
    enable_endpoint_isolation: bool = False
    dry_run: bool = False


@dataclass
class AuditConfig:
    """Configuration for the tamper-proof encrypted audit log."""
    enabled: bool = False
    encrypt: bool = False
    passphrase: str = ""
    rotation_size_mb: int = 50


@dataclass
class FleetConfig:
    enabled: bool = False
    server_url: str = ""
    device_id: str = ""
    enrollment_token: str = ""
    api_key: str = ""
    telemetry_opt_in: bool = False


@dataclass
class SMTPConfig:
    """SMTP server configuration for email delivery."""
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_address: str = ""


@dataclass
class EmailSchedule:
    """Schedule configuration for periodic email reports."""
    frequency: str = "weekly"  # daily, weekly, monthly
    day_of_week: int = 1  # Monday=1, Sunday=7
    hour: int = 8
    minute: int = 0


@dataclass
class EmailReportConfig:
    """Configuration for scheduled email report delivery."""
    enabled: bool = False
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    schedule: EmailSchedule = field(default_factory=EmailSchedule)
    recipients: list[str] = field(default_factory=list)
    subject_prefix: str = "[Sentinel]"
    include_html_attachment: bool = True


@dataclass
class AllowlistConfig:
    """Configuration for the allowlist/exclusion system."""
    enabled: bool = True


@dataclass
class QuarantineConfig:
    """Configuration for file quarantine management."""
    retention_days: int = 30
    max_size_mb: int = 500
    auto_purge: bool = True
    encrypt: bool = True


@dataclass
class GuardConfig:
    """Configuration for real-time file monitoring."""
    enabled: bool = False
    directories: list = field(default_factory=list)
    auto_quarantine: bool = False
    debounce_ms: int = 100


@dataclass
class RuleUpdateConfig:
    """Configuration for malware rule updates."""
    enabled: bool = True
    update_url: str = ""
    auto_update: bool = False
    check_interval_hours: int = 24


@dataclass
class EDRConfig:
    """Configuration for the EDR event timeline."""
    enabled: bool = False
    retention_days: int = 7
    max_size_mb: int = 500


@dataclass
class RealTimeConfig:
    """Configuration for real-time protection engine."""
    enabled: bool = False
    process_monitor: bool = True
    connection_monitor: bool = True
    file_monitor: bool = True


@dataclass
class RansomwareConfig:
    """Configuration for ransomware shield."""
    enabled: bool = False
    canary_enabled: bool = True
    snapshot_interval_minutes: int = 60
    protected_folders: list = field(default_factory=list)
    emergency_response: bool = True


@dataclass
class PlaybookConfig:
    """Configuration for response playbooks."""
    enabled: bool = False
    auto_execute: bool = False
    custom_playbook_dir: str = ""


@dataclass
class SIEMConfigData:
    """Configuration for SIEM/webhook integration."""
    enabled: bool = False
    webhook_url: str = ""
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_format: str = "cef"
    forward_min_severity: str = "low"


@dataclass
class AppControlConfig:
    """Configuration for application control."""
    enabled: bool = False
    mode: str = "disabled"
    learning_days: int = 7


@dataclass
class DeviceControlConfig:
    """Configuration for USB device control."""
    enabled: bool = False
    default_policy: str = "alert"
    allow_hid: bool = True
    allow_storage: bool = True
    allowed_device_ids: list = field(default_factory=list)


@dataclass
class AgentConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    fleet: FleetConfig = field(default_factory=FleetConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    email: EmailReportConfig = field(default_factory=EmailReportConfig)
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    quarantine: QuarantineConfig = field(default_factory=QuarantineConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    rules: RuleUpdateConfig = field(default_factory=RuleUpdateConfig)
    edr: EDRConfig = field(default_factory=EDRConfig)
    realtime: RealTimeConfig = field(default_factory=RealTimeConfig)
    ransomware: RansomwareConfig = field(default_factory=RansomwareConfig)
    playbooks: PlaybookConfig = field(default_factory=PlaybookConfig)
    siem: SIEMConfigData = field(default_factory=SIEMConfigData)
    app_control: AppControlConfig = field(default_factory=AppControlConfig)
    device_control: DeviceControlConfig = field(default_factory=DeviceControlConfig)
    mesh_enabled: bool = False
    edition: AgentEdition = field(default_factory=lambda: _detect_edition())
    log_dir: Path = field(default_factory=lambda: _default_log_dir())
    profile: str = "standard"
    version: str = "4.0.0"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Convert Path objects to strings for serialization
        data["report"]["output_dir"] = str(self.report.output_dir)
        data["log_dir"] = str(self.log_dir)
        return data

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> AgentConfig:
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        config = cls()
        if "scan" in data:
            for k, v in data["scan"].items():
                if k == "depth":
                    v = ScanDepth(v)
                setattr(config.scan, k, v)
        if "report" in data:
            for k, v in data["report"].items():
                if k == "output_dir":
                    v = Path(v)
                setattr(config.report, k, v)
        if "edition" in data:
            config.edition = AgentEdition(data["edition"])
        if "log_dir" in data:
            config.log_dir = Path(data["log_dir"])
        if "profile" in data:
            config.profile = data["profile"]
        return config


def _detect_edition() -> AgentEdition:
    system = platform.system().lower()
    if system == "linux":
        return AgentEdition.SERVER
    return AgentEdition.DESKTOP


def _default_log_dir() -> Path:
    system = platform.system().lower()
    if system == "windows":
        return Path.home() / "AppData" / "Local" / "Sentinel" / "logs"
    elif system == "darwin":
        return Path.home() / "Library" / "Logs" / "Sentinel"
    else:
        return Path("/var/log/sentinel")


def get_platform() -> str:
    return platform.system().lower()


def is_windows() -> bool:
    return get_platform() == "windows"


def is_macos() -> bool:
    return get_platform() == "darwin"


def is_linux() -> bool:
    return get_platform() == "linux"
