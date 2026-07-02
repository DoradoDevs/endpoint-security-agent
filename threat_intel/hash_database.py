"""
Sentinel Agent — Malware Hash Database

Downloads and maintains a local database of known-malicious file hashes
from public threat intelligence sources:

- MalwareBazaar (abuse.ch) — Recent malware samples with SHA-256 hashes
- Feodo Tracker (abuse.ch) — Banking trojan C2 indicators
- Community hash lists — Configurable URL for custom hash feeds

The database is stored locally as a SQLite file for fast O(1) lookups
during file scanning. Supports incremental updates to avoid re-downloading
the entire dataset each time.

SECURITY: All data is stored locally. No file content is ever uploaded.
Only hash values are downloaded from public feeds.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import platform
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.logging import get_logger


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HashEntry:
    """A single malware hash entry."""
    sha256: str
    sha1: str = ""
    md5: str = ""
    malware_family: str = ""
    threat_type: str = ""  # e.g., "trojan", "ransomware", "rat"
    source: str = ""       # e.g., "malwarebazaar", "feodo"
    first_seen: str = ""
    confidence: int = 100  # 0-100 confidence score
    tags: str = ""         # comma-separated tags


# ---------------------------------------------------------------------------
# Feed definitions
# ---------------------------------------------------------------------------

MALWAREBAZAAR_RECENT_URL = "https://bazaar.abuse.ch/export/csv/recent/"
MALWAREBAZAAR_FULL_SHA256_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
FEODO_HASHES_URL = "https://feodotracker.abuse.ch/downloads/malware_hashes.csv"


# ---------------------------------------------------------------------------
# Hash Database
# ---------------------------------------------------------------------------

class HashDatabase:
    """SQLite-backed malware hash database with fast lookup."""

    def __init__(self, db_path: Path | None = None):
        self.log = get_logger()
        self._db_path = db_path or self._default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @staticmethod
    def _default_db_path() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "hash_db" / "malware_hashes.db"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "hash_db" / "malware_hashes.db"
        return Path.home() / ".sentinel" / "hash_db" / "malware_hashes.db"

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS hashes (
                        sha256 TEXT PRIMARY KEY,
                        sha1 TEXT DEFAULT '',
                        md5 TEXT DEFAULT '',
                        malware_family TEXT DEFAULT '',
                        threat_type TEXT DEFAULT '',
                        source TEXT DEFAULT '',
                        first_seen TEXT DEFAULT '',
                        confidence INTEGER DEFAULT 100,
                        tags TEXT DEFAULT '',
                        added_at TEXT DEFAULT ''
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_md5 ON hashes(md5)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sha1 ON hashes(sha1)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_family ON hashes(malware_family)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON hashes(source)")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT DEFAULT ''
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup_sha256(self, sha256: str) -> HashEntry | None:
        """Look up a SHA-256 hash. Returns None if not found."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM hashes WHERE sha256 = ?",
                (sha256.lower(),)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            conn.close()

    def lookup_md5(self, md5: str) -> HashEntry | None:
        """Look up an MD5 hash."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM hashes WHERE md5 = ?",
                (md5.lower(),)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            conn.close()

    def lookup_sha1(self, sha1: str) -> HashEntry | None:
        """Look up a SHA-1 hash."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM hashes WHERE sha1 = ?",
                (sha1.lower(),)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            conn.close()

    def lookup_any(self, file_hash: str) -> HashEntry | None:
        """Look up a hash of any type (auto-detects by length)."""
        h = file_hash.lower().strip()
        if len(h) == 64:
            return self.lookup_sha256(h)
        elif len(h) == 40:
            return self.lookup_sha1(h)
        elif len(h) == 32:
            return self.lookup_md5(h)
        return None

    # ------------------------------------------------------------------
    # Feed updates
    # ------------------------------------------------------------------

    def update_from_malwarebazaar(self) -> tuple[int, str]:
        """Download recent hashes from MalwareBazaar. Returns (count, message)."""
        try:
            import requests
        except ImportError:
            return 0, "requests library not available"

        try:
            self.log.info("[HashDB] Downloading MalwareBazaar recent hashes...")
            resp = requests.get(MALWAREBAZAAR_RECENT_URL, timeout=60,
                                headers={"User-Agent": "Sentinel-Agent/4.0"})
            resp.raise_for_status()

            entries = self._parse_malwarebazaar_csv(resp.text)
            if entries:
                count = self._bulk_insert(entries)
                self._set_metadata("malwarebazaar_last_update",
                                   datetime.now(timezone.utc).isoformat())
                self.log.info(f"[HashDB] MalwareBazaar: {count} hashes added/updated")
                return count, f"MalwareBazaar: {count} hashes"

            return 0, "No entries parsed from MalwareBazaar"

        except Exception as exc:
            msg = f"MalwareBazaar update failed: {exc}"
            self.log.warning(f"[HashDB] {msg}")
            return 0, msg

    def update_from_feodo(self) -> tuple[int, str]:
        """Download hashes from Feodo Tracker. Returns (count, message)."""
        try:
            import requests
        except ImportError:
            return 0, "requests library not available"

        try:
            self.log.info("[HashDB] Downloading Feodo Tracker hashes...")
            resp = requests.get(FEODO_HASHES_URL, timeout=30,
                                headers={"User-Agent": "Sentinel-Agent/4.0"})
            resp.raise_for_status()

            entries = self._parse_feodo_csv(resp.text)
            if entries:
                count = self._bulk_insert(entries)
                self._set_metadata("feodo_last_update",
                                   datetime.now(timezone.utc).isoformat())
                self.log.info(f"[HashDB] Feodo Tracker: {count} hashes added/updated")
                return count, f"Feodo: {count} hashes"

            return 0, "No entries parsed from Feodo"

        except Exception as exc:
            msg = f"Feodo update failed: {exc}"
            self.log.warning(f"[HashDB] {msg}")
            return 0, msg

    def update_from_url(self, url: str, source_name: str = "custom") -> tuple[int, str]:
        """Download a plain-text hash list (one SHA-256 per line)."""
        try:
            import requests
        except ImportError:
            return 0, "requests library not available"

        try:
            resp = requests.get(url, timeout=30,
                                headers={"User-Agent": "Sentinel-Agent/4.0"})
            resp.raise_for_status()

            entries: list[HashEntry] = []
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and len(line) == 64:
                    entries.append(HashEntry(
                        sha256=line.lower(),
                        source=source_name,
                    ))

            if entries:
                count = self._bulk_insert(entries)
                return count, f"{source_name}: {count} hashes"

            return 0, f"No valid hashes found at {url}"

        except Exception as exc:
            return 0, f"Custom feed update failed: {exc}"

    def update_all(self) -> dict[str, Any]:
        """Update from all configured feeds."""
        results: dict[str, Any] = {}

        mb_count, mb_msg = self.update_from_malwarebazaar()
        results["malwarebazaar"] = {"count": mb_count, "message": mb_msg}

        feodo_count, feodo_msg = self.update_from_feodo()
        results["feodo"] = {"count": feodo_count, "message": feodo_msg}

        results["total_new"] = mb_count + feodo_count
        results["total_in_db"] = self.get_total_count()
        return results

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_malwarebazaar_csv(self, text: str) -> list[HashEntry]:
        """Parse MalwareBazaar CSV export."""
        entries: list[HashEntry] = []

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                if len(row) < 8:
                    continue

                # MalwareBazaar CSV format:
                # first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime_type, signature, ...
                first_seen = row[0].strip('" ')
                sha256 = row[1].strip('" ').lower()
                md5 = row[2].strip('" ').lower()
                sha1 = row[3].strip('" ').lower()
                signature = row[8].strip('" ') if len(row) > 8 else ""
                tags = row[9].strip('" ') if len(row) > 9 else ""

                if len(sha256) == 64:
                    entries.append(HashEntry(
                        sha256=sha256,
                        sha1=sha1,
                        md5=md5,
                        malware_family=signature,
                        threat_type="malware",
                        source="malwarebazaar",
                        first_seen=first_seen,
                        tags=tags,
                    ))

            except (StopIteration, csv.Error, IndexError):
                continue

        return entries

    def _parse_feodo_csv(self, text: str) -> list[HashEntry]:
        """Parse Feodo Tracker CSV export."""
        entries: list[HashEntry] = []

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                if len(row) < 3:
                    continue

                # Feodo format varies — try to extract hashes
                for field in row:
                    field = field.strip().lower()
                    if len(field) == 64 and all(c in "0123456789abcdef" for c in field):
                        entries.append(HashEntry(
                            sha256=field,
                            threat_type="banking_trojan",
                            source="feodo",
                            malware_family="feodo",
                        ))
                        break

            except (StopIteration, csv.Error):
                continue

        return entries

    # ------------------------------------------------------------------
    # Database operations
    # ------------------------------------------------------------------

    def _bulk_insert(self, entries: list[HashEntry]) -> int:
        """Insert entries in bulk. Returns count of new entries."""
        if not entries:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                rows = [
                    (e.sha256, e.sha1, e.md5, e.malware_family, e.threat_type,
                     e.source, e.first_seen, e.confidence, e.tags, now)
                    for e in entries
                ]
                conn.executemany(
                    "INSERT OR IGNORE INTO hashes "
                    "(sha256, sha1, md5, malware_family, threat_type, source, "
                    "first_seen, confidence, tags, added_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                inserted = conn.total_changes
                conn.commit()
                return inserted
            finally:
                conn.close()

    def add_hash(self, sha256: str, **kwargs) -> bool:
        """Add a single hash to the database."""
        entry = HashEntry(sha256=sha256.lower(), **kwargs)
        return self._bulk_insert([entry]) > 0

    def get_total_count(self) -> int:
        """Get total number of hashes in the database."""
        conn = sqlite3.connect(str(self._db_path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            total = conn.execute("SELECT COUNT(*) as cnt FROM hashes").fetchone()["cnt"]
            by_source = conn.execute(
                "SELECT source, COUNT(*) as cnt FROM hashes GROUP BY source ORDER BY cnt DESC"
            ).fetchall()
            by_type = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt FROM hashes GROUP BY threat_type ORDER BY cnt DESC"
            ).fetchall()

            return {
                "total_hashes": total,
                "by_source": {r["source"]: r["cnt"] for r in by_source},
                "by_type": {r["threat_type"]: r["cnt"] for r in by_type},
                "db_path": str(self._db_path),
                "db_size_mb": round(self._db_path.stat().st_size / (1024 * 1024), 2)
                if self._db_path.exists() else 0,
                "malwarebazaar_last_update": self._get_metadata("malwarebazaar_last_update"),
                "feodo_last_update": self._get_metadata("feodo_last_update"),
            }
        finally:
            conn.close()

    def _set_metadata(self, key: str, value: str) -> None:
        """Set a metadata key-value pair."""
        conn = sqlite3.connect(str(self._db_path))
        try:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    def _get_metadata(self, key: str) -> str:
        """Get a metadata value."""
        conn = sqlite3.connect(str(self._db_path))
        try:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else ""
        finally:
            conn.close()

    @staticmethod
    def _row_to_entry(row) -> HashEntry:
        """Convert a database row to a HashEntry."""
        return HashEntry(
            sha256=row["sha256"],
            sha1=row["sha1"],
            md5=row["md5"],
            malware_family=row["malware_family"],
            threat_type=row["threat_type"],
            source=row["source"],
            first_seen=row["first_seen"],
            confidence=row["confidence"],
            tags=row["tags"],
        )
