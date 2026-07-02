"""Sentinel Agent — Tamper-Proof Audit Log

HMAC-SHA256 hash chain with optional AES-256-GCM encryption.
Each entry includes a hash of the previous entry, creating a chain
that detects any tampering or deletion.

Format (JSONL — one JSON object per line):
  {"seq": 1, "timestamp": "...", "event": "...", "data": {...}, "chain_hash": "..."}
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.crypto import compute_chain_hash, decrypt_entry, derive_key, encrypt_entry, hmac_sha256
from core.logging import get_logger

# Sentinel value: the genesis hash that seeds every new chain.
GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """A single record in the audit chain."""

    seq: int
    timestamp: str
    event: str
    data: dict[str, Any]
    chain_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event": self.event,
            "data": self.data,
            "chain_hash": self.chain_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEntry:
        return cls(
            seq=d["seq"],
            timestamp=d["timestamp"],
            event=d.get("event", ""),
            data=d.get("data", {}),
            chain_hash=d["chain_hash"],
        )


# ---------------------------------------------------------------------------
# Audit log engine
# ---------------------------------------------------------------------------

class AuditLog:
    """Tamper-proof hash-chain audit log with optional AES-256-GCM encryption."""

    def __init__(
        self,
        log_dir: Path | None = None,
        passphrase: str | None = None,
    ) -> None:
        self.log = get_logger()

        if log_dir is None:
            log_dir = self._default_log_dir()
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_file = self.log_dir / "audit_chain.jsonl"
        self._passphrase = passphrase
        self._encrypt_key: bytes | None = None
        self._salt_file = self.log_dir / "audit_salt.bin"

        # Chain state
        self._last_hash: str = GENESIS_HASH
        self._seq: int = 0

        self._load_state()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_log_dir() -> Path:
        """Platform-appropriate default directory for audit logs."""
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "audit"
        elif system == "darwin":
            return Path.home() / "Library" / "Logs" / "Sentinel" / "audit"
        return Path.home() / ".sentinel" / "audit"

    def _load_state(self) -> None:
        """Restore the last hash and sequence counter from the existing log."""
        if self.log_file.exists():
            try:
                lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    self._last_hash = last.get("chain_hash", GENESIS_HASH)
                    self._seq = last.get("seq", 0)
            except (json.JSONDecodeError, OSError):
                pass

        # Derive encryption key when a passphrase is provided.
        if self._passphrase:
            salt: bytes | None = None
            if self._salt_file.exists():
                salt = self._salt_file.read_bytes()
            self._encrypt_key, new_salt = derive_key(self._passphrase, salt)
            if not self._salt_file.exists():
                self._salt_file.write_bytes(new_salt)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, event: str, data: dict[str, Any] | None = None) -> AuditEntry:
        """Append an event to the audit log and return the new entry.

        Args:
            event: Short event identifier (e.g. ``"scan_started"``).
            data: Arbitrary JSON-serialisable context dict.

        Returns:
            The :class:`AuditEntry` that was written.
        """
        self._seq += 1
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_data = json.dumps(
            {"event": event, "data": data or {}, "timestamp": timestamp},
            sort_keys=True,
        )
        chain_hash = compute_chain_hash(self._last_hash, entry_data)

        entry = AuditEntry(
            seq=self._seq,
            timestamp=timestamp,
            event=event,
            data=data or {},
            chain_hash=chain_hash,
        )

        # Serialise — optionally encrypt the payload.
        line_data = entry.to_dict()
        if self._encrypt_key:
            plaintext = json.dumps({"event": event, "data": data or {}})
            encrypted = encrypt_entry(self._encrypt_key, plaintext)
            line_data["encrypted_payload"] = encrypted
            if encrypted.get("encrypted"):
                # Strip cleartext fields; chain_hash remains visible.
                line_data.pop("event", None)
                line_data.pop("data", None)

        try:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line_data) + "\n")
        except OSError as exc:
            self.log.error(f"Audit log write failed: {exc}")

        self._last_hash = chain_hash
        return entry

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Walk the log and verify every hash link.

        Returns:
            ``(valid, errors)`` — *valid* is ``True`` when the chain is
            intact; *errors* lists human-readable descriptions of any
            broken links.
        """
        if not self.log_file.exists():
            return True, []

        errors: list[str] = []
        prev_hash = GENESIS_HASH

        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            for i, line in enumerate(lines):
                entry_dict = json.loads(line)
                stored_hash = entry_dict.get("chain_hash", "")
                seq = entry_dict.get("seq", i + 1)

                # Recover cleartext event + data (decrypt if necessary).
                if (
                    "encrypted_payload" in entry_dict
                    and entry_dict["encrypted_payload"].get("encrypted")
                ):
                    if self._encrypt_key:
                        plaintext = decrypt_entry(
                            self._encrypt_key, entry_dict["encrypted_payload"]
                        )
                        payload = json.loads(plaintext)
                        event = payload.get("event", "")
                        data = payload.get("data", {})
                    else:
                        errors.append(
                            f"Entry {seq}: encrypted but no passphrase provided"
                        )
                        prev_hash = stored_hash
                        continue
                else:
                    event = entry_dict.get("event", "")
                    data = entry_dict.get("data", {})

                timestamp = entry_dict.get("timestamp", "")
                entry_data = json.dumps(
                    {"event": event, "data": data, "timestamp": timestamp},
                    sort_keys=True,
                )
                expected_hash = compute_chain_hash(prev_hash, entry_data)

                if expected_hash != stored_hash:
                    errors.append(f"Entry {seq}: hash mismatch (chain broken)")

                prev_hash = stored_hash

        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Log parse error: {exc}")

        return len(errors) == 0, errors

    def get_entries(self, limit: int = 100) -> list[AuditEntry]:
        """Read the most recent *limit* audit entries.

        Encrypted payloads are transparently decrypted when the passphrase
        is available; otherwise the event is shown as ``"[encrypted]"``.
        """
        if not self.log_file.exists():
            return []

        entries: list[AuditEntry] = []
        try:
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            for line in lines[-limit:]:
                d = json.loads(line)
                # Decrypt if needed.
                if (
                    "encrypted_payload" in d
                    and d["encrypted_payload"].get("encrypted")
                ):
                    if self._encrypt_key:
                        plaintext = decrypt_entry(
                            self._encrypt_key, d["encrypted_payload"]
                        )
                        payload = json.loads(plaintext)
                        d["event"] = payload.get("event", "")
                        d["data"] = payload.get("data", {})
                    else:
                        d["event"] = "[encrypted]"
                        d["data"] = {}
                entries.append(AuditEntry.from_dict(d))
        except (json.JSONDecodeError, OSError):
            pass

        return entries

    def export(self, output_path: Path) -> int:
        """Export audit log entries to a JSON file for forensic review.

        Args:
            output_path: Destination file (will be overwritten).

        Returns:
            Number of entries exported.
        """
        entries = self.get_entries(limit=10_000)
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "entries": [e.to_dict() for e in entries],
        }
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return len(entries)
