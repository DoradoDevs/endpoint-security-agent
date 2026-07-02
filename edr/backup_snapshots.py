"""
Sentinel Agent — Backup Snapshots

Creates file listing snapshots with hashes for ransomware detection.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from core.logging import get_logger


@dataclass
class FileSnapshot:
    path: str
    sha256: str
    size: int
    mtime: float


@dataclass
class BackupSnapshot:
    snapshot_id: str
    timestamp: str
    directory: str
    file_count: int
    files: list[FileSnapshot] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "directory": self.directory,
            "file_count": self.file_count,
            "files": [
                {
                    "path": f.path,
                    "sha256": f.sha256,
                    "size": f.size,
                    "mtime": f.mtime,
                }
                for f in self.files
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> BackupSnapshot:
        files = [FileSnapshot(**f) for f in data.get("files", [])]
        return cls(
            snapshot_id=data["snapshot_id"],
            timestamp=data["timestamp"],
            directory=data["directory"],
            file_count=data.get("file_count", len(files)),
            files=files,
        )


@dataclass
class SnapshotDiff:
    new_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    potentially_encrypted: list[str] = field(default_factory=list)


class BackupSnapshotManager:
    """Creates and compares file snapshots for ransomware detection."""

    def __init__(self, snapshot_dir: Path | None = None):
        self.log = get_logger()
        self._snapshot_dir = snapshot_dir or self._default_snapshot_dir()
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _default_snapshot_dir() -> Path:
        import platform

        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "snapshots"
        elif system == "darwin":
            return (
                Path.home()
                / "Library"
                / "Application Support"
                / "Sentinel"
                / "snapshots"
            )
        else:
            return Path.home() / ".sentinel" / "snapshots"

    def create_snapshot(
        self, directory: str, max_files: int = 10000
    ) -> BackupSnapshot:
        """Create a snapshot of files in a directory."""
        import uuid

        snapshot_id = str(uuid.uuid4())[:8]
        files = []

        dir_path = Path(directory)
        count = 0

        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                if count >= max_files:
                    break
                filepath = Path(root) / filename
                try:
                    stat = filepath.stat()
                    # Only hash files under 10MB
                    if stat.st_size <= 10 * 1024 * 1024:
                        sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()
                    else:
                        sha256 = ""
                    files.append(
                        FileSnapshot(
                            path=str(filepath),
                            sha256=sha256,
                            size=stat.st_size,
                            mtime=stat.st_mtime,
                        )
                    )
                    count += 1
                except (OSError, PermissionError):
                    pass

        snapshot = BackupSnapshot(
            snapshot_id=snapshot_id,
            timestamp=datetime.now().isoformat(),
            directory=directory,
            file_count=len(files),
            files=files,
        )

        # Save snapshot
        snapshot_file = self._snapshot_dir / f"{snapshot_id}.json"
        snapshot_file.write_text(json.dumps(snapshot.to_dict(), indent=2))

        return snapshot

    def compare_snapshots(
        self, old: BackupSnapshot, new: BackupSnapshot
    ) -> SnapshotDiff:
        """Compare two snapshots. Returns diff."""
        old_files = {f.path: f for f in old.files}
        new_files = {f.path: f for f in new.files}

        diff = SnapshotDiff()

        # New files
        for path in new_files:
            if path not in old_files:
                diff.new_files.append(path)

        # Deleted files
        for path in old_files:
            if path not in new_files:
                diff.deleted_files.append(path)

        # Modified files
        for path, new_snap in new_files.items():
            if path in old_files:
                old_snap = old_files[path]
                if (
                    old_snap.sha256
                    and new_snap.sha256
                    and old_snap.sha256 != new_snap.sha256
                ):
                    diff.modified_files.append(path)
                    # Check if potentially encrypted (significant size change)
                    if old_snap.size > 0 and new_snap.size > 0:
                        ratio = new_snap.size / old_snap.size
                        if ratio > 1.5 or ratio < 0.5:
                            diff.potentially_encrypted.append(path)

        return diff

    def load_snapshot(self, snapshot_id: str) -> BackupSnapshot | None:
        """Load a snapshot by ID."""
        path = self._snapshot_dir / f"{snapshot_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return BackupSnapshot.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    def list_snapshots(self) -> list[dict]:
        """List available snapshots (metadata only)."""
        snapshots = []
        for path in sorted(self._snapshot_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(path.read_text())
                snapshots.append(
                    {
                        "id": data["snapshot_id"],
                        "timestamp": data["timestamp"],
                        "directory": data["directory"],
                        "file_count": data["file_count"],
                    }
                )
            except (json.JSONDecodeError, KeyError):
                pass
        return snapshots
