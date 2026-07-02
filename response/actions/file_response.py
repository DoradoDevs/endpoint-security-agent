"""
Sentinel Agent — File Quarantine Manager

Moves suspicious files to a quarantine directory with full metadata
preservation and restore capability.  Supports XOR encryption of
quarantined files, automatic retention purging, and quota management.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.telemetry import Finding


@dataclass
class QuarantineEntry:
    """Metadata for a quarantined file."""

    quarantine_id: str
    original_path: str
    quarantine_path: str
    sha256: str
    finding_title: str
    finding_severity: str
    timestamp: str
    restored: bool = False
    xor_key: str = ""          # Hex-encoded XOR encryption key
    file_size: int = 0         # Original file size in bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "sha256": self.sha256,
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "timestamp": self.timestamp,
            "restored": self.restored,
            "xor_key": self.xor_key,
            "file_size": self.file_size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuarantineEntry:
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


class FileQuarantineManager:
    """Manages file quarantine with full reversibility."""

    def __init__(
        self,
        quarantine_dir: Path | None = None,
        config: Any = None,
    ) -> None:
        self.log = get_logger()
        self._config = config
        if quarantine_dir is None:
            quarantine_dir = self._default_quarantine_dir()
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = self.quarantine_dir / "manifest.json"

    # ------------------------------------------------------------------
    # Platform helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_quarantine_dir() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "quarantine"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "quarantine"
        return Path.home() / ".sentinel" / "quarantine"

    # ------------------------------------------------------------------
    # XOR encryption
    # ------------------------------------------------------------------

    def _xor_encrypt(self, filepath: Path) -> bytes:
        """XOR file with random 32-byte key.  Returns the key."""
        key = os.urandom(32)
        data = filepath.read_bytes()
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        filepath.write_bytes(encrypted)
        return key

    def _xor_decrypt(self, filepath: Path, key: bytes) -> None:
        """Reverse XOR encryption."""
        data = filepath.read_bytes()
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        filepath.write_bytes(decrypted)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def quarantine(self, filepath: str, finding: Finding) -> tuple[bool, str]:
        """Move file to quarantine with metadata preservation."""
        src = Path(filepath)
        if not src.exists():
            return False, f"File not found: {filepath}"

        q_id = str(uuid.uuid4())[:8]
        # Compute hash and size before moving
        sha256 = self._file_hash(src)
        file_size = src.stat().st_size

        # Create quarantine subdirectory for this entry
        dest_dir = self.quarantine_dir / q_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name

        try:
            shutil.move(str(src), str(dest))
        except (OSError, shutil.Error) as e:
            return False, f"Failed to quarantine: {e}"

        # Determine whether to encrypt
        encrypt_cfg = getattr(self._config, "quarantine", None)
        should_encrypt = encrypt_cfg.encrypt if encrypt_cfg else True

        xor_key_hex = ""
        if should_encrypt:
            xor_key = self._xor_encrypt(dest)
            xor_key_hex = xor_key.hex()

        entry = QuarantineEntry(
            quarantine_id=q_id,
            original_path=str(src),
            quarantine_path=str(dest),
            sha256=sha256,
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            xor_key=xor_key_hex,
            file_size=file_size,
        )

        self._add_to_manifest(entry)
        self.log.info(f"Quarantined: {filepath} -> {dest} (ID: {q_id})")
        return True, f"File quarantined (ID: {q_id})"

    def restore(self, quarantine_id: str) -> tuple[bool, str]:
        """Restore a quarantined file to its original location."""
        manifest = self._load_manifest()
        entry = manifest.get(quarantine_id)
        if entry is None:
            return False, f"Quarantine ID '{quarantine_id}' not found"

        if entry.restored:
            return False, "File already restored"

        src = Path(entry.quarantine_path)
        dest = Path(entry.original_path)

        if not src.exists():
            return False, f"Quarantined file not found: {src}"

        # Decrypt before restoring if encrypted
        if entry.xor_key:
            self._xor_decrypt(src, bytes.fromhex(entry.xor_key))

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest))
        except (OSError, shutil.Error) as e:
            return False, f"Restore failed: {e}"

        entry.restored = True
        self._update_manifest(manifest)
        self.log.info(f"Restored: {dest} from quarantine (ID: {quarantine_id})")
        return True, f"File restored to {dest}"

    # ------------------------------------------------------------------
    # Listing / info
    # ------------------------------------------------------------------

    def list_quarantined(self) -> list[QuarantineEntry]:
        """List all quarantined files."""
        manifest = self._load_manifest()
        return [e for e in manifest.values() if not e.restored]

    def get_info(self, quarantine_id: str) -> QuarantineEntry | None:
        """Get detailed info about a specific quarantined file."""
        manifest = self._load_manifest()
        return manifest.get(quarantine_id)

    def get_total_size(self) -> int:
        """Calculate total bytes in quarantine directory (excluding manifest)."""
        total = 0
        for entry in self.list_quarantined():
            qpath = Path(entry.quarantine_path)
            if qpath.exists():
                total += qpath.stat().st_size
        return total

    # ------------------------------------------------------------------
    # Retention / quota management
    # ------------------------------------------------------------------

    def purge_expired(self, retention_days: int | None = None) -> list[str]:
        """Delete quarantined files older than *retention_days*.

        Returns list of purged quarantine IDs.
        """
        if retention_days is None:
            cfg = getattr(self._config, "quarantine", None)
            retention_days = cfg.retention_days if cfg else 30

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        manifest = self._load_manifest()
        purged: list[str] = []

        for q_id, entry in list(manifest.items()):
            if entry.restored:
                continue
            try:
                entry_dt = datetime.fromisoformat(entry.timestamp)
            except (ValueError, TypeError):
                continue
            if entry_dt < cutoff:
                self._remove_quarantine_files(entry)
                entry.restored = True  # mark so it's excluded from lists
                purged.append(q_id)

        if purged:
            self._update_manifest(manifest)
        return purged

    def purge_by_quota(self, max_size_mb: int | None = None) -> list[str]:
        """If total quarantine exceeds *max_size_mb*, purge oldest first.

        Returns list of purged quarantine IDs.
        """
        if max_size_mb is None:
            cfg = getattr(self._config, "quarantine", None)
            max_size_mb = cfg.max_size_mb if cfg else 500

        max_bytes = max_size_mb * 1024 * 1024
        manifest = self._load_manifest()

        # Collect active entries sorted by timestamp (oldest first)
        active = [
            (q_id, entry)
            for q_id, entry in manifest.items()
            if not entry.restored
        ]
        active.sort(key=lambda pair: pair[1].timestamp)

        total = self.get_total_size()
        purged: list[str] = []

        for q_id, entry in active:
            if total <= max_bytes:
                break
            qpath = Path(entry.quarantine_path)
            entry_size = qpath.stat().st_size if qpath.exists() else 0
            self._remove_quarantine_files(entry)
            entry.restored = True
            total -= entry_size
            purged.append(q_id)

        if purged:
            self._update_manifest(manifest)
        return purged

    def purge_all(self) -> int:
        """Purge all non-restored quarantined files.  Returns count purged."""
        manifest = self._load_manifest()
        count = 0

        for entry in manifest.values():
            if entry.restored:
                continue
            self._remove_quarantine_files(entry)
            entry.restored = True
            count += 1

        if count:
            self._update_manifest(manifest)
        return count

    # ------------------------------------------------------------------
    # Finding helpers
    # ------------------------------------------------------------------

    def is_applicable(self, finding: Finding) -> bool:
        """Check if this handler applies to a given finding."""
        return (
            finding.category in ("File Integrity", "Threat Intelligence", "Malware Indicators")
            and any(k in finding.evidence for k in ("path", "filepath", "file"))
        )

    def get_filepath_from_finding(self, finding: Finding) -> str | None:
        """Extract the file path from a finding's evidence."""
        for key in ("path", "filepath", "file"):
            val = finding.evidence.get(key)
            if val and isinstance(val, str):
                return val
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _file_hash(path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _remove_quarantine_files(self, entry: QuarantineEntry) -> None:
        """Remove the quarantine subdirectory for an entry."""
        qpath = Path(entry.quarantine_path)
        # The file lives inside a per-entry subdirectory
        subdir = qpath.parent
        if subdir.exists() and subdir != self.quarantine_dir:
            shutil.rmtree(str(subdir), ignore_errors=True)
        elif qpath.exists():
            qpath.unlink(missing_ok=True)

    def _load_manifest(self) -> dict[str, QuarantineEntry]:
        if not self.manifest_file.exists():
            return {}
        try:
            data = json.loads(self.manifest_file.read_text())
            return {k: QuarantineEntry.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError):
            return {}

    def _add_to_manifest(self, entry: QuarantineEntry) -> None:
        manifest = self._load_manifest()
        manifest[entry.quarantine_id] = entry
        self._update_manifest(manifest)

    def _update_manifest(self, manifest: dict[str, QuarantineEntry]) -> None:
        try:
            data = {k: v.to_dict() for k, v in manifest.items()}
            self.manifest_file.write_text(json.dumps(data, indent=2))
        except OSError as e:
            self.log.error(f"Manifest write failed: {e}")
