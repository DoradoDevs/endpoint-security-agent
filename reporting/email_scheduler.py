"""
Sentinel Agent — Email Schedule Checker

Determines whether a scheduled email report is due based on the
configured frequency (daily, weekly, monthly) and the last-sent
timestamp persisted in a local JSON state file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.config import EmailReportConfig


class EmailScheduleChecker:
    """Checks if an email report is due based on schedule."""

    def __init__(
        self, config: EmailReportConfig, state_dir: Path | None = None
    ):
        self.config = config
        if state_dir is None:
            state_dir = Path.home() / ".sentinel"
        self._state_file = state_dir / "email_schedule_state.json"

    def is_due(self) -> bool:
        """Check if an email is due based on schedule and last sent time.

        Returns True when the configured interval has elapsed since the
        last send, or when no email has ever been sent.
        """
        if not self.config.enabled:
            return False

        last = self._last_sent()
        if last is None:
            return True

        now = datetime.now(timezone.utc)
        schedule = self.config.schedule
        frequency = schedule.frequency.lower()

        if frequency == "daily":
            # Due if 24 hours have elapsed since last send
            delta = now - last
            return delta.total_seconds() >= 86400

        if frequency == "weekly":
            # Due if 7 days have elapsed since last send
            delta = now - last
            return delta.total_seconds() >= 7 * 86400

        if frequency == "monthly":
            # Due if roughly 30 days have elapsed since last send
            delta = now - last
            return delta.total_seconds() >= 30 * 86400

        # Unknown frequency — not due
        return False

    def mark_sent(self) -> None:
        """Record that an email was just sent."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "last_sent": datetime.now(timezone.utc).isoformat(),
        }
        self._state_file.write_text(json.dumps(state, indent=2))

    def _last_sent(self) -> datetime | None:
        """Get the last sent timestamp.

        Returns:
            A timezone-aware datetime, or None if no state file exists
            or the file is invalid.
        """
        if not self._state_file.exists():
            return None

        try:
            data = json.loads(self._state_file.read_text())
            ts = data.get("last_sent")
            if ts is None:
                return None
            dt = datetime.fromisoformat(ts)
            # Ensure timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (json.JSONDecodeError, ValueError, KeyError):
            return None
