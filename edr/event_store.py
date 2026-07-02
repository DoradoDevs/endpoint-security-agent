"""
Sentinel Agent — EDR Event Store

SQLite-based storage for EDR events with WAL mode for concurrent access.
Supports batch inserts, retention policies, and size limits.
"""

from __future__ import annotations

import json
import os
import platform
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

from edr.event_types import EDREvent, EDREventType


class EventStore:
    """SQLite-backed EDR event store with WAL mode."""

    def __init__(self, db_path: Path | None = None, retention_days: int = 7, max_size_mb: int = 500):
        self._db_path = db_path or self._default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days
        self._max_size_mb = max_size_mb
        self._lock = threading.Lock()
        self._init_db()

    @staticmethod
    def _default_db_path() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "edr" / "events.db"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "edr" / "events.db"
        else:
            return Path.home() / ".sentinel" / "edr" / "events.db"

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source_pid INTEGER DEFAULT 0,
                        source_process TEXT DEFAULT '',
                        target TEXT DEFAULT '',
                        details TEXT DEFAULT '{}',
                        severity TEXT DEFAULT 'info',
                        correlated_finding_id TEXT DEFAULT ''
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_source_pid ON events(source_pid)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)")
                conn.commit()
            finally:
                conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def record_event(self, event: EDREvent) -> None:
        """Record a single event."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO events (id, timestamp, event_type, source_pid, source_process, target, details, severity, correlated_finding_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (event.id, event.timestamp, event.event_type.value, event.source_pid,
                     event.source_process, event.target, json.dumps(event.details),
                     event.severity, event.correlated_finding_id)
                )
                conn.commit()
            finally:
                conn.close()

    def record_events_batch(self, events: list[EDREvent]) -> int:
        """Record multiple events in a single transaction. Returns count inserted."""
        if not events:
            return 0
        with self._lock:
            conn = self._get_conn()
            try:
                rows = [
                    (e.id, e.timestamp, e.event_type.value, e.source_pid,
                     e.source_process, e.target, json.dumps(e.details),
                     e.severity, e.correlated_finding_id)
                    for e in events
                ]
                conn.executemany(
                    "INSERT OR REPLACE INTO events (id, timestamp, event_type, source_pid, source_process, target, details, severity, correlated_finding_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows
                )
                conn.commit()
                return len(rows)
            finally:
                conn.close()

    def get_events(self, limit: int = 500, offset: int = 0,
                   event_type: EDREventType | None = None,
                   severity: str | None = None,
                   since_hours: int | None = None) -> list[EDREvent]:
        """Query events with optional filters."""
        conn = self._get_conn()
        try:
            conditions = []
            params = []

            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type.value)
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            if since_hours:
                cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat()
                conditions.append("timestamp >= ?")
                params.append(cutoff)

            where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_event(row) for row in rows]
        finally:
            conn.close()

    def get_event_by_id(self, event_id: str) -> EDREvent | None:
        """Get a single event by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return self._row_to_event(row) if row else None
        finally:
            conn.close()

    def get_events_by_pid(self, pid: int, limit: int = 100) -> list[EDREvent]:
        """Get all events for a specific process ID."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events WHERE source_pid = ? ORDER BY timestamp DESC LIMIT ?",
                (pid, limit)
            ).fetchall()
            return [self._row_to_event(row) for row in rows]
        finally:
            conn.close()

    def get_events_by_process(self, process_name: str, limit: int = 100) -> list[EDREvent]:
        """Get events by process name (case-insensitive partial match)."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events WHERE LOWER(source_process) LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{process_name.lower()}%", limit)
            ).fetchall()
            return [self._row_to_event(row) for row in rows]
        finally:
            conn.close()

    def get_event_counts(self, hours: int = 24) -> dict[str, int]:
        """Get event counts by type for the last N hours."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY event_type ORDER BY cnt DESC",
                (cutoff,)
            ).fetchall()
            return {row["event_type"]: row["cnt"] for row in rows}
        finally:
            conn.close()

    def get_total_count(self) -> int:
        """Get total number of events."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def purge_old_events(self, retention_days: int | None = None) -> int:
        """Delete events older than retention period. Returns count deleted."""
        days = retention_days or self._retention_days
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                conn.commit()
                deleted = cursor.rowcount
                if deleted > 0:
                    conn.execute("VACUUM")
                return deleted
            finally:
                conn.close()

    def enforce_size_limit(self) -> int:
        """Delete oldest events if DB exceeds size limit. Returns count deleted."""
        size_mb = self.get_db_size_mb()
        if size_mb <= self._max_size_mb:
            return 0

        # Delete oldest 20% of events
        total = self.get_total_count()
        delete_count = max(1, total // 5)

        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp ASC LIMIT ?)",
                    (delete_count,)
                )
                conn.commit()
                deleted = cursor.rowcount
                conn.execute("VACUUM")
                return deleted
            finally:
                conn.close()

    def get_db_size_mb(self) -> float:
        """Get the database file size in MB."""
        try:
            return self._db_path.stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

    def clear_all(self) -> int:
        """Delete all events. Returns count deleted."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("DELETE FROM events")
                conn.commit()
                count = cursor.rowcount
                conn.execute("VACUUM")
                return count
            finally:
                conn.close()

    def _row_to_event(self, row) -> EDREvent:
        """Convert a database row to an EDREvent."""
        details = {}
        try:
            details = json.loads(row["details"]) if row["details"] else {}
        except (json.JSONDecodeError, TypeError):
            pass

        return EDREvent(
            id=row["id"],
            timestamp=row["timestamp"],
            event_type=EDREventType(row["event_type"]),
            source_pid=row["source_pid"],
            source_process=row["source_process"],
            target=row["target"],
            details=details,
            severity=row["severity"],
            correlated_finding_id=row["correlated_finding_id"],
        )
