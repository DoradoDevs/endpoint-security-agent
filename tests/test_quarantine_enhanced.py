"""Tests for enhanced quarantine manager — encryption, retention, quotas."""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from response.actions.file_response import FileQuarantineManager, QuarantineEntry
from core.config import AgentConfig, Severity
from core.telemetry import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    category: str = "Malware Indicators",
    evidence: dict | None = None,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding(
        title="Malware detected",
        description="Test finding",
        severity=severity,
        category=category,
        scanner="TestScanner",
        evidence=evidence or {},
    )


def _write_file(directory: Path, name: str, content: bytes = b"payload") -> Path:
    """Create a file with the given content and return its path."""
    p = directory / name
    p.write_bytes(content)
    return p


# ===========================================================================
# XOR Encryption
# ===========================================================================

class TestXOREncryption:
    """Low-level XOR encrypt/decrypt tests."""

    def test_xor_encrypt_decrypt_roundtrip(self):
        """Encrypting then decrypting should return the original content."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            target = _write_file(Path(tmp), "roundtrip.bin", b"hello world 1234")
            original = target.read_bytes()

            key = manager._xor_encrypt(target)
            assert len(key) == 32

            manager._xor_decrypt(target, key)
            assert target.read_bytes() == original

    def test_encrypted_content_differs(self):
        """After encryption the on-disk bytes must differ from the original."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            original_data = b"sensitive information that should be obscured"
            target = _write_file(Path(tmp), "secret.dat", original_data)

            manager._xor_encrypt(target)
            encrypted_data = target.read_bytes()

            assert encrypted_data != original_data
            assert len(encrypted_data) == len(original_data)

    def test_decrypt_with_wrong_key(self):
        """Decrypting with the wrong key should not recover original content."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            original_data = b"correct horse battery staple"
            target = _write_file(Path(tmp), "wrongkey.bin", original_data)

            _correct_key = manager._xor_encrypt(target)
            wrong_key = os.urandom(32)

            manager._xor_decrypt(target, wrong_key)
            assert target.read_bytes() != original_data


# ===========================================================================
# Enhanced Quarantine (encrypt on quarantine, decrypt on restore)
# ===========================================================================

class TestEnhancedQuarantine:
    """Integration tests for quarantine with XOR encryption."""

    def test_quarantine_encrypts_file(self):
        """The quarantined copy on disk should be encrypted (differ from original)."""
        with tempfile.TemporaryDirectory() as tmp:
            original_data = b"this is the original file content"
            src = _write_file(Path(tmp), "evil.exe", original_data)

            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            finding = _make_finding(evidence={"path": str(src)})
            success, msg = manager.quarantine(str(src), finding)
            assert success is True

            entries = manager.list_quarantined()
            assert len(entries) == 1

            quarantined_path = Path(entries[0].quarantine_path)
            quarantined_data = quarantined_path.read_bytes()
            assert quarantined_data != original_data

    def test_restore_decrypts_file(self):
        """Restoring a quarantined file should yield the exact original bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            original_data = b"important document content\xff\x00\x80"
            src = _write_file(Path(tmp), "important.doc", original_data)

            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            finding = _make_finding()
            success, _ = manager.quarantine(str(src), finding)
            assert success

            entries = manager.list_quarantined()
            q_id = entries[0].quarantine_id

            ok, _ = manager.restore(q_id)
            assert ok
            assert src.read_bytes() == original_data

    def test_backward_compat_no_xor_key(self):
        """An entry without an xor_key (old format) should restore normally."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            # Manually craft a legacy manifest entry (no xor_key field)
            q_id = "legacy01"
            sub = q_dir / q_id
            sub.mkdir(parents=True, exist_ok=True)
            dest = sub / "old_file.txt"
            original_data = b"legacy content"
            dest.write_bytes(original_data)

            original_location = Path(tmp) / "restored_old_file.txt"
            entry_dict = {
                q_id: {
                    "quarantine_id": q_id,
                    "original_path": str(original_location),
                    "quarantine_path": str(dest),
                    "sha256": "a" * 64,
                    "finding_title": "Legacy finding",
                    "finding_severity": "high",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "restored": False,
                    # NOTE: no xor_key, no file_size — old format
                }
            }
            manager.manifest_file.write_text(json.dumps(entry_dict, indent=2))

            ok, _ = manager.restore(q_id)
            assert ok
            assert original_location.read_bytes() == original_data

    def test_file_size_recorded(self):
        """file_size should equal the source file size before quarantine."""
        with tempfile.TemporaryDirectory() as tmp:
            data = b"A" * 12345
            src = _write_file(Path(tmp), "sized.bin", data)
            expected_size = src.stat().st_size

            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            finding = _make_finding()
            manager.quarantine(str(src), finding)

            entries = manager.list_quarantined()
            assert entries[0].file_size == expected_size


# ===========================================================================
# Retention Policy
# ===========================================================================

class TestRetentionPolicy:
    """Tests for time-based purging of quarantined files."""

    def _quarantine_with_age(
        self, manager: FileQuarantineManager, tmp: str, name: str, days_old: int,
    ) -> str:
        """Quarantine a file and then rewrite its timestamp to be *days_old* days ago."""
        src = _write_file(Path(tmp), name, b"data-" + name.encode())
        finding = _make_finding()
        ok, _ = manager.quarantine(str(src), finding)
        assert ok

        manifest = manager._load_manifest()
        # Find the entry we just added (latest)
        for q_id, entry in manifest.items():
            if entry.original_path == str(src):
                old_ts = datetime.now(timezone.utc) - timedelta(days=days_old)
                entry.timestamp = old_ts.isoformat()
                break
        manager._update_manifest(manifest)
        return q_id

    def test_purge_expired_removes_old(self):
        """Entries older than retention_days should be purged."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            old_id = self._quarantine_with_age(manager, tmp, "old.bin", days_old=60)

            purged = manager.purge_expired(retention_days=30)
            assert old_id in purged
            assert len(manager.list_quarantined()) == 0

    def test_purge_expired_keeps_recent(self):
        """Entries newer than retention_days should be kept."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            self._quarantine_with_age(manager, tmp, "recent.bin", days_old=5)

            purged = manager.purge_expired(retention_days=30)
            assert purged == []
            assert len(manager.list_quarantined()) == 1

    def test_purge_expired_skips_restored(self):
        """Already-restored entries should not be purged again."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            q_id = self._quarantine_with_age(manager, tmp, "restored.bin", days_old=60)

            # Restore the file first
            manager.restore(q_id)

            purged = manager.purge_expired(retention_days=30)
            assert purged == []

    def test_purge_with_custom_days(self):
        """Custom retention_days parameter should override config/default."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            self._quarantine_with_age(manager, tmp, "mid.bin", days_old=10)

            # With 30-day retention, 10-day-old entry should survive
            purged_30 = manager.purge_expired(retention_days=30)
            assert purged_30 == []

            # With 5-day retention, 10-day-old entry should be purged
            purged_5 = manager.purge_expired(retention_days=5)
            assert len(purged_5) == 1


# ===========================================================================
# Quota Management
# ===========================================================================

class TestQuotaManagement:
    """Tests for size-based quota enforcement."""

    def test_purge_by_quota_removes_oldest(self):
        """When over quota the oldest entries should be removed first."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            finding = _make_finding()
            ids = []
            # Create three 1-MB files (unencrypted so sizes are predictable)
            config = MagicMock()
            config.quarantine.encrypt = False
            manager._config = config

            for i in range(3):
                src = _write_file(Path(tmp), f"big_{i}.bin", b"X" * (1024 * 1024))
                ok, msg = manager.quarantine(str(src), finding)
                assert ok
                # Extract ID from message
                q_id = msg.split("ID: ")[1].rstrip(")")
                ids.append(q_id)

            # Total ~ 3 MB.  Set quota to 2 MB — oldest should be purged.
            purged = manager.purge_by_quota(max_size_mb=2)
            assert len(purged) >= 1
            # The oldest entry (first created) should be among purged
            assert ids[0] in purged

    def test_purge_by_quota_under_limit(self):
        """When under quota nothing should be purged."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            config = MagicMock()
            config.quarantine.encrypt = False
            manager = FileQuarantineManager(quarantine_dir=q_dir, config=config)

            finding = _make_finding()
            src = _write_file(Path(tmp), "small.bin", b"tiny")
            manager.quarantine(str(src), finding)

            purged = manager.purge_by_quota(max_size_mb=500)
            assert purged == []
            assert len(manager.list_quarantined()) == 1

    def test_get_total_size(self):
        """get_total_size should reflect the actual bytes on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            config = MagicMock()
            config.quarantine.encrypt = False
            manager = FileQuarantineManager(quarantine_dir=q_dir, config=config)

            finding = _make_finding()
            data = b"A" * 2048
            src = _write_file(Path(tmp), "measure.bin", data)
            manager.quarantine(str(src), finding)

            total = manager.get_total_size()
            assert total == len(data)

    def test_purge_all(self):
        """purge_all should remove every active quarantined file."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            config = MagicMock()
            config.quarantine.encrypt = False
            manager = FileQuarantineManager(quarantine_dir=q_dir, config=config)

            finding = _make_finding()
            for i in range(4):
                src = _write_file(Path(tmp), f"purge_{i}.bin", f"data{i}".encode())
                manager.quarantine(str(src), finding)

            assert len(manager.list_quarantined()) == 4

            count = manager.purge_all()
            assert count == 4
            assert len(manager.list_quarantined()) == 0


# ===========================================================================
# Quarantine Info
# ===========================================================================

class TestQuarantineInfo:
    """Tests for get_info."""

    def test_get_info_exists(self):
        """get_info should return the entry for a valid quarantine ID."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            src = _write_file(Path(tmp), "info.bin", b"info content")
            finding = _make_finding()
            ok, msg = manager.quarantine(str(src), finding)
            assert ok

            q_id = msg.split("ID: ")[1].rstrip(")")
            entry = manager.get_info(q_id)

            assert entry is not None
            assert entry.quarantine_id == q_id
            assert entry.finding_title == "Malware detected"
            assert entry.sha256  # non-empty hash

    def test_get_info_not_found(self):
        """get_info should return None for a nonexistent quarantine ID."""
        with tempfile.TemporaryDirectory() as tmp:
            q_dir = Path(tmp) / "quarantine"
            manager = FileQuarantineManager(quarantine_dir=q_dir)

            assert manager.get_info("does-not-exist") is None
