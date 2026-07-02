"""Tests for Sentinel Agent — Ransomware Shield (canary files, backup snapshots, shield)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.canary_files import CanaryFile, CanaryFileManager
from edr.backup_snapshots import (
    BackupSnapshot,
    BackupSnapshotManager,
    FileSnapshot,
    SnapshotDiff,
)
from edr.ransomware_shield import RansomwareShield
from core.config import AgentConfig


# ---------------------------------------------------------------------------
# TestCanaryFiles
# ---------------------------------------------------------------------------


class TestCanaryFiles:
    """Tests for CanaryFileManager."""

    def test_deploy_canaries(self, tmp_path):
        """Deploy canary files to temp dirs, verify files created."""
        dir1 = tmp_path / "Documents"
        dir2 = tmp_path / "Desktop"
        dir1.mkdir()
        dir2.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        count = mgr.deploy_canaries(directories=[str(dir1), str(dir2)])

        assert count == 2
        assert len(mgr.get_canaries()) == 2

        # Verify files exist on disk
        for canary in mgr.get_canaries():
            assert Path(canary.path).exists()
            assert canary.status == "active"
            assert canary.sha256  # Non-empty hash

        # Cleanup
        mgr.remove_canaries()

    def test_check_canaries_clean(self, tmp_path):
        """No modification, no triggers."""
        test_dir = tmp_path / "clean_test"
        test_dir.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        mgr.deploy_canaries(directories=[str(test_dir)])

        triggered = mgr.check_canaries()

        assert triggered == []
        for canary in mgr.get_canaries():
            assert canary.status == "active"

        mgr.remove_canaries()

    def test_check_canaries_deleted(self, tmp_path):
        """Delete a canary file, verify it is triggered."""
        test_dir = tmp_path / "delete_test"
        test_dir.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        mgr.deploy_canaries(directories=[str(test_dir)])

        # Delete the canary file
        canary = mgr.get_canaries()[0]
        Path(canary.path).unlink()

        triggered = mgr.check_canaries()

        assert len(triggered) == 1
        assert triggered[0].path == canary.path
        assert triggered[0].status == "triggered"

    def test_check_canaries_modified(self, tmp_path):
        """Modify canary content, verify triggered."""
        test_dir = tmp_path / "modify_test"
        test_dir.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        mgr.deploy_canaries(directories=[str(test_dir)])

        # Modify the canary file content (clear hidden attribute on Windows first)
        canary = mgr.get_canaries()[0]
        canary_path = Path(canary.path)
        import os as _os
        if hasattr(_os, 'name') and _os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(canary_path), 0x80)  # NORMAL
            except Exception:
                pass
        canary_path.write_bytes(b"ransomware was here")

        triggered = mgr.check_canaries()

        assert len(triggered) == 1
        assert triggered[0].path == canary.path
        assert triggered[0].status == "triggered"

    def test_remove_canaries(self, tmp_path):
        """Deploy then remove canaries, verify cleaned up."""
        dir1 = tmp_path / "remove_test_1"
        dir2 = tmp_path / "remove_test_2"
        dir1.mkdir()
        dir2.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        mgr.deploy_canaries(directories=[str(dir1), str(dir2)])

        # Verify files exist
        paths = [c.path for c in mgr.get_canaries()]
        for p in paths:
            assert Path(p).exists()

        removed = mgr.remove_canaries()

        assert removed == 2
        assert mgr.get_canaries() == []
        for p in paths:
            assert not Path(p).exists()

    def test_get_canaries(self, tmp_path):
        """Verify list returns deployed canaries with correct metadata."""
        test_dir = tmp_path / "list_test"
        test_dir.mkdir()

        mgr = CanaryFileManager(canary_dir=tmp_path)
        mgr.deploy_canaries(directories=[str(test_dir)])

        canaries = mgr.get_canaries()

        assert len(canaries) == 1
        canary = canaries[0]
        assert isinstance(canary, CanaryFile)
        assert canary.status == "active"
        assert canary.sha256
        assert canary.deployed_at
        assert str(test_dir) in canary.path

        mgr.remove_canaries()


# ---------------------------------------------------------------------------
# TestBackupSnapshots
# ---------------------------------------------------------------------------


class TestBackupSnapshots:
    """Tests for BackupSnapshotManager."""

    def test_create_snapshot(self, tmp_path):
        """Create temp files, snapshot, verify counts."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "file1.txt").write_text("hello world")
        (data_dir / "file2.txt").write_text("sentinel agent")
        (data_dir / "file3.bin").write_bytes(b"\x00\x01\x02\x03")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)
        snapshot = mgr.create_snapshot(str(data_dir))

        assert snapshot.file_count == 3
        assert len(snapshot.files) == 3
        assert snapshot.directory == str(data_dir)
        assert snapshot.snapshot_id
        assert snapshot.timestamp

        # Verify hashes are correct
        for fs in snapshot.files:
            content = Path(fs.path).read_bytes()
            assert fs.sha256 == hashlib.sha256(content).hexdigest()

    def test_compare_snapshots_no_changes(self, tmp_path):
        """Two identical snapshots show no diff."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "file1.txt").write_text("content1")
        (data_dir / "file2.txt").write_text("content2")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        snap1 = mgr.create_snapshot(str(data_dir))
        snap2 = mgr.create_snapshot(str(data_dir))

        diff = mgr.compare_snapshots(snap1, snap2)

        assert diff.new_files == []
        assert diff.modified_files == []
        assert diff.deleted_files == []
        assert diff.potentially_encrypted == []

    def test_compare_snapshots_new_file(self, tmp_path):
        """Add file between snapshots, show new_files."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "file1.txt").write_text("original")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        snap1 = mgr.create_snapshot(str(data_dir))

        # Add a new file
        (data_dir / "file2_new.txt").write_text("new file")
        snap2 = mgr.create_snapshot(str(data_dir))

        diff = mgr.compare_snapshots(snap1, snap2)

        assert len(diff.new_files) == 1
        assert "file2_new.txt" in diff.new_files[0]

    def test_compare_snapshots_modified(self, tmp_path):
        """Modify file content between snapshots, show modified_files."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        target_file = data_dir / "target.txt"
        target_file.write_text("original content")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        snap1 = mgr.create_snapshot(str(data_dir))

        # Modify the file
        target_file.write_text("modified content!!!")
        snap2 = mgr.create_snapshot(str(data_dir))

        diff = mgr.compare_snapshots(snap1, snap2)

        assert len(diff.modified_files) == 1
        assert "target.txt" in diff.modified_files[0]

    def test_compare_snapshots_deleted(self, tmp_path):
        """Delete file between snapshots, show deleted_files."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "keep.txt").write_text("keep me")
        (data_dir / "delete_me.txt").write_text("goodbye")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        snap1 = mgr.create_snapshot(str(data_dir))

        # Delete a file
        (data_dir / "delete_me.txt").unlink()
        snap2 = mgr.create_snapshot(str(data_dir))

        diff = mgr.compare_snapshots(snap1, snap2)

        assert len(diff.deleted_files) == 1
        assert "delete_me.txt" in diff.deleted_files[0]

    def test_load_snapshot(self, tmp_path):
        """Save and load snapshot by ID."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "file.txt").write_text("test content")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        original = mgr.create_snapshot(str(data_dir))

        loaded = mgr.load_snapshot(original.snapshot_id)

        assert loaded is not None
        assert loaded.snapshot_id == original.snapshot_id
        assert loaded.directory == original.directory
        assert loaded.file_count == original.file_count
        assert len(loaded.files) == len(original.files)
        assert loaded.files[0].sha256 == original.files[0].sha256

    def test_list_snapshots(self, tmp_path):
        """Multiple snapshots are listed with metadata."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "file.txt").write_text("content")

        snapshot_dir = tmp_path / "snapshots"
        mgr = BackupSnapshotManager(snapshot_dir=snapshot_dir)

        mgr.create_snapshot(str(data_dir))
        mgr.create_snapshot(str(data_dir))
        mgr.create_snapshot(str(data_dir))

        listing = mgr.list_snapshots()

        assert len(listing) == 3
        for entry in listing:
            assert "id" in entry
            assert "timestamp" in entry
            assert "directory" in entry
            assert "file_count" in entry


# ---------------------------------------------------------------------------
# TestRansomwareShield
# ---------------------------------------------------------------------------


class TestRansomwareShield:
    """Tests for RansomwareShield."""

    def test_shield_init(self):
        """Verify initialization with config and callback."""
        config = AgentConfig()
        callback = MagicMock()

        shield = RansomwareShield(config=config, event_callback=callback)

        assert shield.config is config
        assert shield._event_callback is callback
        assert shield._alerts == []
        assert shield._canary_check_interval == 30
        assert shield._snapshot_interval == 3600

    def test_ransomware_detection_fires_event(self):
        """Mock canary trigger, verify alert callback is fired with EDR event."""
        config = AgentConfig()
        callback = MagicMock()

        shield = RansomwareShield(config=config, event_callback=callback)

        # Create fake triggered canaries
        triggered = [
            CanaryFile(
                path="/tmp/canary1.dat",
                sha256="abc123",
                status="triggered",
            ),
            CanaryFile(
                path="/tmp/canary2.dat",
                sha256="def456",
                status="triggered",
            ),
        ]

        shield._on_ransomware_detected(triggered)

        # Verify callback was called with an EDR event
        assert callback.call_count == 1
        event = callback.call_args[0][0]
        assert event.event_type.value == "ransomware_alert"
        assert event.severity == "critical"
        assert event.details["canaries_triggered"] == 2

        # Verify alert was recorded
        assert len(shield.get_alerts()) == 1
        alert = shield.get_alerts()[0]
        assert alert["type"] == "ransomware_alert"
        assert alert["canaries_triggered"] == 2
        assert len(alert["paths"]) == 2
