"""Compliance framework models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    CIS = "cis"
    NIST_800_53 = "nist"
    SOC2 = "soc2"


class ControlStatus(str, Enum):
    """Status of a compliance control evaluation."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"


@dataclass
class ComplianceControl:
    """A single compliance control from a framework."""

    id: str
    title: str
    description: str
    category: str
    framework: ComplianceFramework
    # Scanner categories that map to this control
    mapped_categories: list[str] = field(default_factory=list)
    # Severity levels that indicate a fail for this control
    fail_severities: list[str] = field(default_factory=lambda: ["critical", "high"])


@dataclass
class ControlResult:
    """Result of evaluating a single compliance control."""

    control: ComplianceControl
    status: ControlStatus
    findings: list[Any] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.id,
            "title": self.control.title,
            "category": self.control.category,
            "framework": self.control.framework.value,
            "status": self.status.value,
            "finding_count": len(self.findings),
            "notes": self.notes,
        }


@dataclass
class ComplianceResult:
    """Aggregated result of evaluating all controls in a framework."""

    framework: ComplianceFramework
    controls: list[ControlResult] = field(default_factory=list)

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.FAIL)

    @property
    def partial(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.PARTIAL)

    @property
    def compliance_percentage(self) -> float:
        """Calculate percentage of assessed controls that passed."""
        assessed = [c for c in self.controls if c.status != ControlStatus.NOT_ASSESSED]
        if not assessed:
            return 100.0
        passed = sum(1 for c in assessed if c.status == ControlStatus.PASS)
        return round((passed / len(assessed)) * 100, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "total_controls": self.total_controls,
            "passed": self.passed,
            "failed": self.failed,
            "partial": self.partial,
            "compliance_percentage": self.compliance_percentage,
            "controls": [c.to_dict() for c in self.controls],
        }
