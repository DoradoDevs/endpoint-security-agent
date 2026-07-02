"""
Sentinel Agent — Telemetry & Scan Results

Data structures for scan findings, telemetry collection, and result aggregation.
All data stays local — no external transmission without explicit configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from core.config import Severity


@dataclass
class Finding:
    """A single security finding from any scanner."""

    title: str
    description: str
    severity: Severity
    category: str
    scanner: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cve_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "scanner": self.scanner,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "timestamp": self.timestamp,
        }


@dataclass
class SystemInfo:
    """Baseline system information collected at scan start."""

    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    cpu_count: int = 0
    total_memory_gb: float = 0.0
    python_version: str = ""
    agent_version: str = ""
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    platform_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "architecture": self.architecture,
            "cpu_count": self.cpu_count,
            "total_memory_gb": self.total_memory_gb,
            "python_version": self.python_version,
            "agent_version": self.agent_version,
            "scan_timestamp": self.scan_timestamp,
            "platform_details": self.platform_details,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete scan session."""

    system_info: SystemInfo = field(default_factory=SystemInfo)
    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    risk_score: float = 0.0
    risk_grade: str = "Unknown"
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for sev in Severity:
            matches = [f for f in self.findings if f.severity == sev]
            if matches:
                result[sev.value] = matches
        return result

    def findings_by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.category, []).append(f)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_info": self.system_info.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "risk_score": self.risk_score,
                "risk_grade": self.risk_grade,
                "scanners_run": self.scanners_run,
                "scan_duration_seconds": self.scan_duration_seconds,
            },
            "errors": self.errors,
        }
