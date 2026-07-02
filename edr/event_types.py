"""
Sentinel Agent — EDR Event Types

Defines event types and the EDREvent dataclass for the endpoint
detection and response timeline.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EDREventType(str, Enum):
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    REGISTRY_MODIFY = "registry_modify"
    LOGIN_ATTEMPT = "login_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RANSOMWARE_ALERT = "ransomware_alert"
    CANARY_TRIGGERED = "canary_triggered"
    THREAT_DETECTED = "threat_detected"
    RESPONSE_ACTION = "response_action"


@dataclass
class EDREvent:
    event_type: EDREventType
    source_process: str = ""
    target: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source_pid: int = 0
    correlated_finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "source_pid": self.source_pid,
            "source_process": self.source_process,
            "target": self.target,
            "details": self.details,
            "severity": self.severity,
            "correlated_finding_id": self.correlated_finding_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> EDREvent:
        return cls(
            id=data.get("id", str(uuid.uuid4())[:12]),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            event_type=EDREventType(data["event_type"]),
            source_pid=data.get("source_pid", 0),
            source_process=data.get("source_process", ""),
            target=data.get("target", ""),
            details=data.get("details", {}),
            severity=data.get("severity", "info"),
            correlated_finding_id=data.get("correlated_finding_id", ""),
        )
