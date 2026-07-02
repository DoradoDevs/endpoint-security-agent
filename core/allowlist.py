"""Sentinel Agent — Allowlist / Exclusion Manager

Maintains a persistent JSON-backed allowlist of hashes, file-path globs,
and process names that scanners should skip.  Each entry can optionally
be scoped to specific scanners, so a hash allowlisted for MalwareScanner
will still be flagged by IOCScanner unless explicitly included.

Storage location (platform-dependent):
  Windows : %LOCALAPPDATA%/Sentinel/allowlist/allowlist.json
  macOS   : ~/Library/Application Support/Sentinel/allowlist/allowlist.json
  Linux   : ~/.sentinel/allowlist/allowlist.json
"""

from __future__ import annotations

import fnmatch
import json
import platform
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.logging import get_logger


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AllowlistEntry:
    """A single allowlist record."""

    id: str
    entry_type: str          # "hash", "path", "process"
    value: str               # SHA-256 hash, glob pattern, or process name
    scanner_scope: list[str] = field(default_factory=list)
    reason: str = ""
    added_timestamp: str = ""
    added_by: str = "cli"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entry_type": self.entry_type,
            "value": self.value,
            "scanner_scope": self.scanner_scope,
            "reason": self.reason,
            "added_timestamp": self.added_timestamp,
            "added_by": self.added_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AllowlistEntry:
        return cls(
            id=data["id"],
            entry_type=data["entry_type"],
            value=data["value"],
            scanner_scope=data.get("scanner_scope", []),
            reason=data.get("reason", ""),
            added_timestamp=data.get("added_timestamp", ""),
            added_by=data.get("added_by", "cli"),
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class AllowlistManager:
    """Manages a JSON-backed allowlist of hashes, paths, and processes."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.log = get_logger()

        if data_dir is None:
            data_dir = self._default_data_dir()

        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.allowlist_file = self.data_dir / "allowlist.json"

    # ------------------------------------------------------------------
    # Platform default
    # ------------------------------------------------------------------

    @staticmethod
    def _default_data_dir() -> Path:
        """Return the platform-appropriate allowlist directory."""
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "allowlist"
        elif system == "darwin":
            return (
                Path.home()
                / "Library"
                / "Application Support"
                / "Sentinel"
                / "allowlist"
            )
        return Path.home() / ".sentinel" / "allowlist"

    # ------------------------------------------------------------------
    # Public add helpers
    # ------------------------------------------------------------------

    def add_hash(
        self,
        sha256: str,
        reason: str = "",
        scanner_scope: list[str] | None = None,
        added_by: str = "cli",
    ) -> AllowlistEntry:
        """Add a SHA-256 hash to the allowlist."""
        return self._add_entry("hash", sha256.lower(), reason, scanner_scope, added_by)

    def add_path(
        self,
        pattern: str,
        reason: str = "",
        scanner_scope: list[str] | None = None,
        added_by: str = "cli",
    ) -> AllowlistEntry:
        """Add a file-path glob pattern to the allowlist."""
        return self._add_entry("path", pattern, reason, scanner_scope, added_by)

    def add_process(
        self,
        name: str,
        reason: str = "",
        scanner_scope: list[str] | None = None,
        added_by: str = "cli",
    ) -> AllowlistEntry:
        """Add a process name to the allowlist."""
        return self._add_entry("process", name, reason, scanner_scope, added_by)

    # ------------------------------------------------------------------
    # Remove
    # ------------------------------------------------------------------

    def remove(self, entry_id: str) -> tuple[bool, str]:
        """Remove an entry by its ID.

        Returns:
            ``(True, description)`` on success, ``(False, reason)`` on failure.
        """
        entries = self._load()
        if entry_id not in entries:
            return False, f"Entry '{entry_id}' not found"

        removed = entries.pop(entry_id)
        self._save(entries)
        return True, f"Removed {removed.entry_type} entry: {removed.value}"

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_entries(self, entry_type: str | None = None) -> list[AllowlistEntry]:
        """Return all entries, optionally filtered by *entry_type*."""
        entries = self._load()
        if entry_type is None:
            return list(entries.values())
        return [e for e in entries.values() if e.entry_type == entry_type]

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def is_hash_allowed(self, sha256: str, scanner_name: str = "") -> bool:
        """Return ``True`` if *sha256* is allowlisted (case-insensitive)."""
        sha_lower = sha256.lower()
        for entry in self._load().values():
            if entry.entry_type != "hash":
                continue
            if entry.value.lower() == sha_lower:
                if self._scope_matches(entry, scanner_name):
                    return True
        return False

    def is_path_excluded(self, filepath: str, scanner_name: str = "") -> bool:
        """Return ``True`` if *filepath* matches any allowlisted path glob."""
        for entry in self._load().values():
            if entry.entry_type != "path":
                continue
            if self._matches_path_pattern(filepath, entry.value):
                if self._scope_matches(entry, scanner_name):
                    return True
        return False

    def is_process_excluded(self, process_name: str, scanner_name: str = "") -> bool:
        """Return ``True`` if *process_name* is allowlisted (case-insensitive)."""
        name_lower = process_name.lower()
        for entry in self._load().values():
            if entry.entry_type != "process":
                continue
            if entry.value.lower() == name_lower:
                if self._scope_matches(entry, scanner_name):
                    return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scope_matches(entry: AllowlistEntry, scanner_name: str) -> bool:
        """Check whether *scanner_name* falls within the entry's scope.

        An empty ``scanner_scope`` means the entry applies to **all** scanners.
        """
        if not entry.scanner_scope:
            return True
        if not scanner_name:
            return True
        return scanner_name in entry.scanner_scope

    @staticmethod
    def _matches_path_pattern(filepath: str, pattern: str) -> bool:
        """Match *filepath* against a glob *pattern*.

        - Normalises all separators to forward slashes for cross-platform
          consistency.
        - Supports ``**`` for recursive directory matching.
        - Uses :func:`fnmatch.fnmatch` for single-level wildcards.
        """
        norm_path = filepath.replace("\\", "/").lower()
        norm_pattern = pattern.replace("\\", "/").lower()

        # Handle ** recursive matching
        if "**" in norm_pattern:
            parts = norm_pattern.split("**")
            if len(parts) == 2:
                prefix, suffix = parts
                prefix = prefix.rstrip("/")
                suffix = suffix.lstrip("/")

                if prefix and suffix:
                    # e.g. /home/user/**/file.txt or /home/user/**/*.tmp
                    if not norm_path.startswith(prefix):
                        return False
                    # Extract the part after the prefix
                    remainder = norm_path[len(prefix):]
                    remainder = remainder.lstrip("/")
                    # The suffix pattern should match the filename (last component)
                    # or the tail of the path
                    if "/" in remainder:
                        filename = remainder.rsplit("/", 1)[-1]
                    else:
                        filename = remainder
                    return fnmatch.fnmatch(filename, suffix)
                elif prefix:
                    # e.g. /home/user/**
                    return norm_path.startswith(prefix)
                elif suffix:
                    # e.g. **/*.log — match filename regardless of directory
                    if "/" in norm_path:
                        filename = norm_path.rsplit("/", 1)[-1]
                    else:
                        filename = norm_path
                    return fnmatch.fnmatch(filename, suffix)
                else:
                    # Bare ** — matches everything
                    return True

        return fnmatch.fnmatch(norm_path, norm_pattern)

    def _add_entry(
        self,
        entry_type: str,
        value: str,
        reason: str,
        scanner_scope: list[str] | None,
        added_by: str,
    ) -> AllowlistEntry:
        """Create, persist, and return a new :class:`AllowlistEntry`."""
        entry_id = uuid.uuid4().hex[:8]
        entry = AllowlistEntry(
            id=entry_id,
            entry_type=entry_type,
            value=value,
            scanner_scope=scanner_scope or [],
            reason=reason or f"Allowlisted {entry_type}",
            added_timestamp=datetime.now(timezone.utc).isoformat(),
            added_by=added_by,
        )

        entries = self._load()
        entries[entry_id] = entry
        self._save(entries)
        return entry

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, AllowlistEntry]:
        """Load allowlist entries from disk.

        Returns an empty dict when the file does not exist or cannot be parsed.
        """
        if not self.allowlist_file.exists():
            return {}

        try:
            raw = self.allowlist_file.read_text(encoding="utf-8")
            data = json.loads(raw)
            return {
                eid: AllowlistEntry.from_dict(edata) for eid, edata in data.items()
            }
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            self.log.warning(f"Failed to load allowlist: {exc}")
            return {}

    def _save(self, entries: dict[str, AllowlistEntry]) -> None:
        """Atomically write allowlist entries to disk."""
        data = {eid: entry.to_dict() for eid, entry in entries.items()}
        try:
            tmp_file = self.allowlist_file.with_suffix(".tmp")
            tmp_file.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
            tmp_file.replace(self.allowlist_file)
        except OSError as exc:
            self.log.error(f"Failed to save allowlist: {exc}")
