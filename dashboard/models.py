"""
Sentinel Dashboard — Data Models

SQLite-backed device registry and scan result storage for the fleet dashboard.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator


def _default_db_path() -> Path:
    """Default database path for the dashboard."""
    import platform as _plat
    system = _plat.system().lower()
    if system == "windows":
        base = Path.home() / "AppData" / "Local" / "Sentinel"
    elif system == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Sentinel"
    else:
        base = Path.home() / ".sentinel"
    base.mkdir(parents=True, exist_ok=True)
    return base / "fleet_dashboard.db"


@dataclass
class DeviceRecord:
    """A device in the fleet registry."""

    device_id: str
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    agent_version: str = ""
    last_scan: str = ""
    last_risk_score: float = 0.0
    last_risk_grade: str = ""
    status: str = "active"
    enrolled_at: str = ""
    tags: str = ""  # JSON list stored as string

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "last_scan": self.last_scan,
            "last_risk_score": self.last_risk_score,
            "last_risk_grade": self.last_risk_grade,
            "status": self.status,
            "enrolled_at": self.enrolled_at,
            "tags": json.loads(self.tags) if self.tags else [],
        }


@dataclass
class ScanRecord:
    """A scan result record."""

    id: int = 0
    device_id: str = ""
    timestamp: str = ""
    risk_score: float = 0.0
    risk_grade: str = ""
    findings_count: int = 0
    scanners_run: str = ""  # JSON list
    errors: str = ""  # JSON list
    severity_breakdown: str = ""  # JSON dict
    category_breakdown: str = ""  # JSON dict

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "findings_count": self.findings_count,
            "scanners_run": json.loads(self.scanners_run) if self.scanners_run else [],
            "errors": json.loads(self.errors) if self.errors else [],
            "severity_breakdown": json.loads(self.severity_breakdown) if self.severity_breakdown else {},
            "category_breakdown": json.loads(self.category_breakdown) if self.category_breakdown else {},
        }


class DashboardDB:
    """SQLite database for fleet dashboard data."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or _default_db_path()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    agent_version TEXT,
                    last_scan TEXT,
                    last_risk_score REAL DEFAULT 0,
                    last_risk_grade TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    enrolled_at TEXT,
                    tags TEXT DEFAULT '[]'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score REAL DEFAULT 0,
                    risk_grade TEXT DEFAULT '',
                    findings_count INTEGER DEFAULT 0,
                    scanners_run TEXT DEFAULT '[]',
                    errors TEXT DEFAULT '[]',
                    severity_breakdown TEXT DEFAULT '{}',
                    category_breakdown TEXT DEFAULT '{}',
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    config_json TEXT DEFAULT '{}',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_policies (
                    device_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    assigned_at TEXT,
                    PRIMARY KEY (device_id, policy_id),
                    FOREIGN KEY (device_id) REFERENCES devices(device_id),
                    FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
                )
            """)
            conn.commit()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # === Device Operations ===

    def register_device(self, device: DeviceRecord) -> None:
        """Register or update a device in the fleet."""
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO devices
                    (device_id, hostname, os_name, os_version, agent_version,
                     last_scan, last_risk_score, last_risk_grade, status,
                     enrolled_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id, device.hostname, device.os_name,
                device.os_version, device.agent_version, device.last_scan,
                device.last_risk_score, device.last_risk_grade,
                device.status, device.enrolled_at, device.tags,
            ))
            conn.commit()

    def get_device(self, device_id: str) -> DeviceRecord | None:
        """Get a device by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row:
                return DeviceRecord(**dict(row))
            return None

    def list_devices(self, status: str = "") -> list[DeviceRecord]:
        """List all devices, optionally filtered by status."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM devices WHERE status = ? ORDER BY hostname",
                    (status,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM devices ORDER BY hostname"
                ).fetchall()
            return [DeviceRecord(**dict(row)) for row in rows]

    def remove_device(self, device_id: str) -> bool:
        """Remove a device from the fleet."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM devices WHERE device_id = ?", (device_id,)
            )
            conn.execute(
                "DELETE FROM scan_results WHERE device_id = ?", (device_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_fleet_summary(self) -> dict[str, Any]:
        """Get summary statistics for the entire fleet."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'active'"
            ).fetchone()[0]
            avg_score_row = conn.execute(
                "SELECT AVG(last_risk_score) FROM devices WHERE status = 'active'"
            ).fetchone()
            avg_score = round(avg_score_row[0] or 0, 1)

            grade_dist = {}
            for row in conn.execute(
                "SELECT last_risk_grade, COUNT(*) FROM devices "
                "WHERE status = 'active' GROUP BY last_risk_grade"
            ).fetchall():
                grade_dist[row[0] or "Unknown"] = row[1]

            return {
                "total_devices": total,
                "active_devices": active,
                "average_risk_score": avg_score,
                "grade_distribution": grade_dist,
            }

    # === Scan Result Operations ===

    def store_scan_result(self, scan: ScanRecord) -> int:
        """Store a scan result and update the device's last scan info."""
        with self._connect() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_results
                    (device_id, timestamp, risk_score, risk_grade,
                     findings_count, scanners_run, errors,
                     severity_breakdown, category_breakdown)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.device_id, scan.timestamp, scan.risk_score,
                scan.risk_grade, scan.findings_count, scan.scanners_run,
                scan.errors, scan.severity_breakdown, scan.category_breakdown,
            ))

            # Update device's last scan info
            conn.execute("""
                UPDATE devices SET
                    last_scan = ?,
                    last_risk_score = ?,
                    last_risk_grade = ?
                WHERE device_id = ?
            """, (scan.timestamp, scan.risk_score, scan.risk_grade, scan.device_id))

            conn.commit()
            return cursor.lastrowid or 0

    def get_device_scans(
        self, device_id: str, limit: int = 50
    ) -> list[ScanRecord]:
        """Get scan history for a device."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE device_id = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            return [ScanRecord(**dict(row)) for row in rows]

    def get_recent_scans(self, limit: int = 100) -> list[ScanRecord]:
        """Get the most recent scans across all devices."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [ScanRecord(**dict(row)) for row in rows]

    # === Policy Operations ===

    def store_policy(self, policy_id: str, name: str, description: str,
                     config_json: str) -> None:
        """Store or update a policy."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO policies
                    (policy_id, name, description, config_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, COALESCE(
                    (SELECT created_at FROM policies WHERE policy_id = ?), ?
                ), ?)
            """, (policy_id, name, description, config_json, policy_id, now, now))
            conn.commit()

    def assign_policy(self, device_id: str, policy_id: str) -> None:
        """Assign a policy to a device."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO device_policies
                    (device_id, policy_id, assigned_at)
                VALUES (?, ?, ?)
            """, (device_id, policy_id, now))
            conn.commit()

    def get_device_policy(self, device_id: str) -> dict[str, Any] | None:
        """Get the policy assigned to a device."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT p.* FROM policies p
                JOIN device_policies dp ON p.policy_id = dp.policy_id
                WHERE dp.device_id = ?
                ORDER BY dp.assigned_at DESC LIMIT 1
            """, (device_id,)).fetchone()
            if row:
                return dict(row)
            return None
