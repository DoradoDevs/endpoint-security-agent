"""
Sentinel Agent — Response Audit Log

Persistent, append-only audit log of all response actions taken.
Stores records in JSONL format following the core/logging.py pattern.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from core.logging import get_logger
from response.models import ResponseRecord, ResponseStatus


class ResponseAuditLog:
    """Persistent audit trail of response actions."""

    def __init__(self, log_dir: Path | None = None):
        self.log = get_logger()
        if log_dir is None:
            log_dir = self._default_log_dir()
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "response_audit.jsonl"

    @staticmethod
    def _default_log_dir() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "logs"
        elif system == "darwin":
            return Path.home() / "Library" / "Logs" / "Sentinel"
        return Path.home() / ".sentinel" / "logs"

    def record(self, entry: ResponseRecord) -> None:
        """Append a response record to the audit log."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except OSError as e:
            self.log.error(f"Audit log write failed: {e}")

    def get_history(self, limit: int = 100) -> list[ResponseRecord]:
        """Read recent response history."""
        if not self.log_file.exists():
            return []

        records: list[ResponseRecord] = []
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            for line in lines[-limit:]:
                data = json.loads(line)
                records.append(ResponseRecord(
                    action_name=data["action_name"],
                    response_type=data["response_type"],
                    status=data["status"],
                    finding_title=data["finding_title"],
                    finding_severity=data["finding_severity"],
                    target=data["target"],
                    message=data.get("message", ""),
                    timestamp=data.get("timestamp", ""),
                    rollback_available=data.get("rollback_available", False),
                    metadata=data.get("metadata", {}),
                    action_id=data.get("action_id", data.get("timestamp", "")[:8]),
                ))
        except (OSError, json.JSONDecodeError, KeyError) as e:
            self.log.error(f"Audit log read failed: {e}")

        return records

    def get_rollback_candidates(self) -> list[ResponseRecord]:
        """Get executed actions that can be rolled back."""
        history = self.get_history()
        return [
            r for r in history
            if r.status == ResponseStatus.EXECUTED and r.rollback_available
        ]

    def get_record_by_id(self, action_id: str) -> ResponseRecord | None:
        """Find a specific response record by its action_id."""
        history = self.get_history(limit=1000)
        for record in history:
            if getattr(record, "action_id", "") == action_id:
                return record
        return None
