"""
Sentinel Agent — Threat Response Data Models

Response types, statuses, actions, and audit records.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ResponseType(str, Enum):
    """Categories of automated response actions."""

    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_CONNECTION = "block_connection"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    ALERT_ONLY = "alert_only"


class ResponseStatus(str, Enum):
    """Outcome status of a response action."""

    PENDING = "pending"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


class ResponseLevel(str, Enum):
    """How aggressive the response policy is, tied to SecurityProfile."""

    ALERT_ONLY = "alert_only"
    LOG_AND_ALERT = "log_and_alert"
    PROMPT = "prompt"
    AUTO_RESPOND = "auto_respond"


@dataclass
class ResponseRecord:
    """Audit record of a response action taken."""

    action_name: str
    response_type: ResponseType
    status: ResponseStatus
    finding_title: str
    finding_severity: str
    target: str
    message: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    rollback_available: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "response_type": self.response_type.value
            if isinstance(self.response_type, ResponseType)
            else self.response_type,
            "status": self.status.value
            if isinstance(self.status, ResponseStatus)
            else self.status,
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "target": self.target,
            "message": self.message,
            "timestamp": self.timestamp,
            "rollback_available": self.rollback_available,
            "metadata": self.metadata,
            "action_id": self.action_id,
        }
