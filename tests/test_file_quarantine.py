"""Tests for the File Quarantine Manager."""

import tempfile
from pathlib import Path

from core.config import Severity
from core.telemetry import Finding
from response.actions.file_response import FileQuarantineManager, QuarantineEntry


class TestFileQuarantineManager:
    """Tests for FileQuarantineManager."""

    def _make_finding(
        self,
        category: str = "Malware Indicators",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            title="Malware detected",
            description="Test",
            severity=Severity.CRITICAL,
            category=category,
            scanner="TestScanner",
            evidence=evidence or {},
        )

    def test_quarantine_moves_file(self):
        """Quarantine should move file to quarantine directory."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create a test file
            test_file = Path(tmp) / "evil.exe"
            test_file.write_text("malicious content")

            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)

            finding = self._make_finding(evidence={"path": str(test_file)})
            success, msg = manager.quarantine(str(test_file), finding)

            assert success is True
            assert "quarantined" in msg
            assert not test_file.exists()  # Original should be gone

    def test_quarantine_preserves_hash(self):
        """Quarantine should record the SHA-256 hash."""
        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "evil.exe"
            test_file.write_text("malicious content")

            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)

            finding = self._make_finding()
            manager.quarantine(str(test_file), finding)

            entries = manager.list_quarantined()
            assert len(entries) == 1
            assert len(entries[0].sha256) == 64  # SHA-256 hex length

    def test_restore_returns_file(self):
        """Restore should move file back to original location."""
        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "important.txt"
            test_file.write_text("important data")
            original_content = test_file.read_text()

            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)

            finding = self._make_finding()
            manager.quarantine(str(test_file), finding)
            assert not test_file.exists()

            entries = manager.list_quarantined()
            q_id = entries[0].quarantine_id

            success, msg = manager.restore(q_id)
            assert success is True
            assert test_file.exists()
            assert test_file.read_text() == original_content

    def test_restore_invalid_id(self):
        """Restore with invalid ID should fail gracefully."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = FileQuarantineManager(quarantine_dir=Path(tmp))
            success, msg = manager.restore("nonexistent")
            assert success is False
            assert "not found" in msg

    def test_restore_already_restored(self):
        """Double restore should fail."""
        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "file.txt"
            test_file.write_text("data")

            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)

            finding = self._make_finding()
            manager.quarantine(str(test_file), finding)

            entries = manager.list_quarantined()
            q_id = entries[0].quarantine_id

            manager.restore(q_id)
            success, msg = manager.restore(q_id)
            assert success is False
            assert "already restored" in msg

    def test_quarantine_nonexistent_file(self):
        """Quarantine of nonexistent file should fail."""
        with tempfile.TemporaryDirectory() as tmp:
            manager = FileQuarantineManager(quarantine_dir=Path(tmp))
            finding = self._make_finding()
            success, msg = manager.quarantine("/nonexistent/file.txt", finding)
            assert success is False
            assert "not found" in msg

    def test_list_quarantined_excludes_restored(self):
        """list_quarantined should not include restored files."""
        with tempfile.TemporaryDirectory() as tmp:
            f1 = Path(tmp) / "f1.txt"
            f2 = Path(tmp) / "f2.txt"
            f1.write_text("1")
            f2.write_text("2")

            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)

            finding = self._make_finding()
            manager.quarantine(str(f1), finding)
            manager.quarantine(str(f2), finding)

            entries = manager.list_quarantined()
            assert len(entries) == 2

            manager.restore(entries[0].quarantine_id)

            entries = manager.list_quarantined()
            assert len(entries) == 1

    def test_is_applicable_correct_categories(self):
        """is_applicable should match expected category + evidence combos."""
        manager = FileQuarantineManager()

        f1 = self._make_finding(category="File Integrity", evidence={"path": "/etc/passwd"})
        assert manager.is_applicable(f1) is True

        f2 = self._make_finding(category="Malware Indicators", evidence={"filepath": "/tmp/x"})
        assert manager.is_applicable(f2) is True

        f3 = self._make_finding(category="Threat Intelligence", evidence={"file": "/tmp/y"})
        assert manager.is_applicable(f3) is True

    def test_not_applicable_wrong_category(self):
        """is_applicable should reject wrong categories."""
        manager = FileQuarantineManager()
        f = self._make_finding(category="Network Security", evidence={"path": "/tmp/x"})
        assert manager.is_applicable(f) is False

    def test_not_applicable_no_path(self):
        """is_applicable should reject when no path in evidence."""
        manager = FileQuarantineManager()
        f = self._make_finding(category="Malware Indicators", evidence={"pid": 123})
        assert manager.is_applicable(f) is False

    def test_get_filepath_from_finding(self):
        """get_filepath_from_finding should try path/filepath/file keys."""
        manager = FileQuarantineManager()

        f1 = self._make_finding(evidence={"path": "/a/b"})
        assert manager.get_filepath_from_finding(f1) == "/a/b"

        f2 = self._make_finding(evidence={"filepath": "/c/d"})
        assert manager.get_filepath_from_finding(f2) == "/c/d"

        f3 = self._make_finding(evidence={"file": "/e/f"})
        assert manager.get_filepath_from_finding(f3) == "/e/f"

        f4 = self._make_finding(evidence={"pid": 123})
        assert manager.get_filepath_from_finding(f4) is None

    def test_quarantine_entry_serialization(self):
        """QuarantineEntry should round-trip through to_dict/from_dict."""
        entry = QuarantineEntry(
            quarantine_id="abc123",
            original_path="/tmp/evil.exe",
            quarantine_path="/q/abc123/evil.exe",
            sha256="a" * 64,
            finding_title="Malware",
            finding_severity="critical",
            timestamp="2024-01-01T00:00:00Z",
        )
        data = entry.to_dict()
        restored = QuarantineEntry.from_dict(data)
        assert restored.quarantine_id == entry.quarantine_id
        assert restored.original_path == entry.original_path
        assert restored.sha256 == entry.sha256
        assert restored.restored is False

    def test_multiple_quarantine_manifest(self):
        """Multiple quarantines should all be tracked in manifest."""
        with tempfile.TemporaryDirectory() as tmp:
            quarantine_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=quarantine_dir)
            finding = self._make_finding()

            for i in range(5):
                f = Path(tmp) / f"file_{i}.txt"
                f.write_text(f"content_{i}")
                manager.quarantine(str(f), finding)

            entries = manager.list_quarantined()
            assert len(entries) == 5
