"""
Sentinel Agent — IOC Database

File-based IOC database with efficient in-memory lookup tables.
Follows the NVDCache pattern: JSON files in ~/.sentinel/cache/threat_intel/,
TTL-based expiry, and lazy loading.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any

from core.logging import get_logger
from threat_intel.models import IOCEntry, IOCType


class IOCDatabase:
    """File-based IOC database with efficient lookup by type."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int = 3600 * 6,  # 6 hours
    ):
        self.log = get_logger()
        self.ttl = ttl_seconds

        if cache_dir is None:
            cache_dir = self._default_cache_dir()
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory lookup tables keyed by IOC value
        self._ip_index: dict[str, IOCEntry] = {}
        self._domain_index: dict[str, IOCEntry] = {}
        self._hash_index: dict[str, IOCEntry] = {}
        self._url_index: dict[str, IOCEntry] = {}
        self._loaded = False

    @staticmethod
    def _default_cache_dir() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "cache" / "threat_intel"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "cache" / "threat_intel"
        return Path.home() / ".sentinel" / "cache" / "threat_intel"

    def load(self) -> None:
        """Load all IOC indexes from disk into memory."""
        self._ip_index = self._load_index("ip_addresses.json")
        self._domain_index = self._load_index("domains.json")
        self._hash_index = self._load_index("file_hashes.json")
        self._url_index = self._load_index("urls.json")
        self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def lookup_ip(self, ip: str) -> IOCEntry | None:
        """Check if an IP is a known-bad indicator."""
        self._ensure_loaded()
        return self._ip_index.get(ip)

    def lookup_domain(self, domain: str) -> IOCEntry | None:
        """Check if a domain is a known-bad indicator."""
        self._ensure_loaded()
        return self._domain_index.get(domain.lower())

    def lookup_hash(self, file_hash: str) -> IOCEntry | None:
        """Check if a file hash matches known malware."""
        self._ensure_loaded()
        return self._hash_index.get(file_hash.lower())

    def lookup_url(self, url: str) -> IOCEntry | None:
        """Check if a URL is a known-bad indicator."""
        self._ensure_loaded()
        return self._url_index.get(url)

    def add_entries(self, entries: list[IOCEntry]) -> int:
        """Add IOC entries to the database. Returns count of new entries added."""
        self._ensure_loaded()
        added = 0

        for entry in entries:
            index = self._index_for_type(entry.ioc_type)
            if index is None:
                continue
            key = entry.value.lower() if entry.ioc_type != IOCType.IP_ADDRESS else entry.value
            if key not in index:
                added += 1
            index[key] = entry

        # Persist to disk after adding
        if added > 0:
            self._save_all()

        return added

    def get_stats(self) -> dict[str, int]:
        """Return counts of IOCs by type."""
        self._ensure_loaded()
        return {
            "ip_addresses": len(self._ip_index),
            "domains": len(self._domain_index),
            "file_hashes": len(self._hash_index),
            "urls": len(self._url_index),
            "total": len(self._ip_index) + len(self._domain_index)
            + len(self._hash_index) + len(self._url_index),
        }

    def needs_refresh(self, feed_name: str) -> bool:
        """Check if a feed's data has expired (TTL-based)."""
        meta = self._load_metadata()
        last_refresh = meta.get(feed_name, 0)
        return (time.time() - last_refresh) > self.ttl

    def mark_refreshed(self, feed_name: str) -> None:
        """Update the last-refresh timestamp for a feed."""
        meta = self._load_metadata()
        meta[feed_name] = time.time()
        self._save_metadata(meta)

    def clear(self) -> None:
        """Clear all IOC data."""
        self._ip_index.clear()
        self._domain_index.clear()
        self._hash_index.clear()
        self._url_index.clear()
        self._save_all()

    def _index_for_type(self, ioc_type: IOCType) -> dict[str, IOCEntry] | None:
        """Get the appropriate index for an IOC type."""
        if ioc_type == IOCType.IP_ADDRESS:
            return self._ip_index
        elif ioc_type == IOCType.DOMAIN:
            return self._domain_index
        elif ioc_type in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256):
            return self._hash_index
        elif ioc_type == IOCType.URL:
            return self._url_index
        return None

    def _save_all(self) -> None:
        """Persist all indexes to disk."""
        self._save_index("ip_addresses.json", self._ip_index)
        self._save_index("domains.json", self._domain_index)
        self._save_index("file_hashes.json", self._hash_index)
        self._save_index("urls.json", self._url_index)

    def _save_index(self, filename: str, index: dict[str, IOCEntry]) -> None:
        """Save an index to disk as JSON."""
        cache_file = self.cache_dir / filename
        try:
            data = {
                "timestamp": time.time(),
                "entries": {k: v.to_dict() for k, v in index.items()},
            }
            cache_file.write_text(json.dumps(data))
        except OSError as e:
            self.log.debug(f"IOC index write failed: {e}")

    def _load_index(self, filename: str) -> dict[str, IOCEntry]:
        """Load an index from disk. Returns empty dict if not found or expired."""
        cache_file = self.cache_dir / filename
        if not cache_file.exists():
            return {}

        try:
            data = json.loads(cache_file.read_text())
            entries = {}
            for key, entry_data in data.get("entries", {}).items():
                entries[key] = IOCEntry.from_dict(entry_data)
            return entries
        except (json.JSONDecodeError, OSError, KeyError) as e:
            self.log.debug(f"IOC index load failed for {filename}: {e}")
            return {}

    def _load_metadata(self) -> dict[str, float]:
        """Load feed refresh metadata."""
        meta_file = self.cache_dir / "metadata.json"
        if not meta_file.exists():
            return {}
        try:
            return json.loads(meta_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_metadata(self, meta: dict[str, float]) -> None:
        """Save feed refresh metadata."""
        meta_file = self.cache_dir / "metadata.json"
        try:
            meta_file.write_text(json.dumps(meta))
        except OSError as e:
            self.log.debug(f"Metadata write failed: {e}")
