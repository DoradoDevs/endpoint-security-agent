"""
Sentinel Agent — EDR Timeline Query

High-level query interface for EDR event timeline analysis.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from edr.event_store import EventStore
from edr.event_types import EDREvent, EDREventType


class TimelineQuery:
    """High-level query interface for EDR event timeline."""

    def __init__(self, store: EventStore):
        self._store = store

    def query_events(
        self,
        hours: int | None = None,
        event_type: EDREventType | str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        severity: str | None = None,
        limit: int = 500,
    ) -> list[EDREvent]:
        """Query events with flexible filters."""
        # Convert string event type to enum
        if isinstance(event_type, str):
            try:
                event_type = EDREventType(event_type)
            except ValueError:
                event_type = None

        # PID-specific query
        if pid is not None:
            return self._store.get_events_by_pid(pid, limit=limit)

        # Process name query
        if process_name:
            return self._store.get_events_by_process(process_name, limit=limit)

        # General query
        return self._store.get_events(
            limit=limit,
            event_type=event_type,
            severity=severity,
            since_hours=hours,
        )

    def get_process_timeline(self, pid: int) -> list[EDREvent]:
        """Get all events related to a process (by PID)."""
        return self._store.get_events_by_pid(pid, limit=500)

    def get_incident_timeline(self, finding_id: str, window_minutes: int = 5) -> list[EDREvent]:
        """Get events around an incident (finding), within a time window."""
        # First find the event correlated to this finding
        events = self._store.get_events(limit=1000)
        target_event = None
        for e in events:
            if e.correlated_finding_id == finding_id:
                target_event = e
                break

        if not target_event:
            return []

        # Get events within the time window
        try:
            center_time = datetime.fromisoformat(target_event.timestamp)
            start = (center_time - timedelta(minutes=window_minutes)).isoformat()
            end = (center_time + timedelta(minutes=window_minutes)).isoformat()
        except ValueError:
            return [target_event]

        all_events = self._store.get_events(limit=1000)
        return [e for e in all_events if start <= e.timestamp <= end]

    def get_event_counts(self, hours: int = 24) -> dict[str, int]:
        """Get event counts by type for the last N hours."""
        return self._store.get_event_counts(hours=hours)

    def get_summary(self, hours: int = 24) -> dict[str, Any]:
        """Get a summary of recent EDR activity."""
        counts = self._store.get_event_counts(hours=hours)
        total = sum(counts.values())

        # Get severity breakdown
        events = self._store.get_events(limit=10000, since_hours=hours)
        severity_counts = {}
        for e in events:
            severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

        return {
            "total_events": total,
            "event_type_counts": counts,
            "severity_counts": severity_counts,
            "hours_covered": hours,
            "db_size_mb": round(self._store.get_db_size_mb(), 2),
        }

    def get_threats(self, hours: int = 24) -> list[EDREvent]:
        """Get only threat-related events."""
        threat_types = {
            EDREventType.THREAT_DETECTED,
            EDREventType.RANSOMWARE_ALERT,
            EDREventType.CANARY_TRIGGERED,
            EDREventType.PRIVILEGE_ESCALATION,
        }
        events = self._store.get_events(limit=500, since_hours=hours)
        return [e for e in events if e.event_type in threat_types]
