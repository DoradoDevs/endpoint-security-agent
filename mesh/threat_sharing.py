"""
Sentinel Agent — Mesh Threat Sharing

Converts local high-severity findings into ``ThreatAlert`` objects and
shares them with mesh peers.  Incoming alerts are deduplicated so each
finding is processed only once.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.config import Severity
from core.telemetry import Finding


# Ordered list for threshold comparison (highest first).
_SEVERITY_ORDER: list[str] = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
]


@dataclass
class ThreatAlert:
    """A finding packaged for sharing with mesh peers."""

    finding_title: str
    finding_severity: str
    finding_category: str
    source_device: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_dict(self) -> dict[str, Any]:
        """Serialise the alert to a plain dictionary."""
        return {
            "alert_id": self.alert_id,
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "finding_category": self.finding_category,
            "source_device": self.source_device,
            "timestamp": self.timestamp,
            "evidence_summary": self.evidence_summary,
        }

    @classmethod
    def from_finding(cls, finding: Finding, device_id: str) -> ThreatAlert:
        """Create a ``ThreatAlert`` from a local ``Finding``."""
        return cls(
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            finding_category=finding.category,
            source_device=device_id,
            evidence_summary=dict(finding.evidence) if finding.evidence else {},
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatAlert:
        """Reconstruct a ``ThreatAlert`` from a plain dictionary."""
        return cls(
            finding_title=data["finding_title"],
            finding_severity=data["finding_severity"],
            finding_category=data["finding_category"],
            source_device=data["source_device"],
            timestamp=data.get("timestamp", ""),
            evidence_summary=data.get("evidence_summary", {}),
            alert_id=data.get("alert_id", uuid.uuid4().hex[:16]),
        )


class ThreatSharingService:
    """Shares high-severity findings with mesh peers and deduplicates
    incoming alerts."""

    def __init__(self, min_severity: str = "high") -> None:
        self.min_severity = min_severity
        self._seen_alerts: set[str] = set()  # alert_id deduplication
        self._received: list[ThreatAlert] = []

    # ------------------------------------------------------------------
    # Outbound
    # ------------------------------------------------------------------

    def should_share(self, finding: Finding) -> bool:
        """Return ``True`` if the finding meets the severity threshold."""
        try:
            threshold_idx = _SEVERITY_ORDER.index(self.min_severity)
        except ValueError:
            threshold_idx = 1  # default to HIGH
        try:
            finding_idx = _SEVERITY_ORDER.index(finding.severity.value)
        except ValueError:
            return False
        return finding_idx <= threshold_idx

    def create_alert(self, finding: Finding, device_id: str) -> ThreatAlert:
        """Build a ``ThreatAlert`` from a local ``Finding``."""
        return ThreatAlert.from_finding(finding, device_id)

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def receive_alert(self, alert: ThreatAlert) -> bool:
        """Process a received alert.

        Returns ``True`` if the alert is new (not a duplicate).
        """
        if alert.alert_id in self._seen_alerts:
            return False
        self._seen_alerts.add(alert.alert_id)
        self._received.append(alert)
        return True

    def get_received_alerts(self) -> list[ThreatAlert]:
        """Return a copy of all received (deduplicated) alerts."""
        return list(self._received)
