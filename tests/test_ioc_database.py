"""Tests for the IOC database."""

import json
import tempfile
import time
from pathlib import Path

from threat_intel.ioc_database import IOCDatabase
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


class TestIOCDatabase:
    """Tests for IOCDatabase CRUD and persistence."""

    def _make_db(self, tmp_dir: str) -> IOCDatabase:
        return IOCDatabase(cache_dir=Path(tmp_dir), ttl_seconds=3600)

    def _make_ip_entry(self, ip: str = "1.2.3.4") -> IOCEntry:
        return IOCEntry(
            value=ip,
            ioc_type=IOCType.IP_ADDRESS,
            threat_category=ThreatCategory.C2_SERVER,
            source="test_feed",
            confidence=90,
            description="Test C2 server",
        )

    def _make_hash_entry(self, h: str = "a" * 64) -> IOCEntry:
        return IOCEntry(
            value=h,
            ioc_type=IOCType.FILE_HASH_SHA256,
            threat_category=ThreatCategory.MALWARE,
            source="test_feed",
            confidence=95,
            description="Test malware hash",
        )

    def _make_domain_entry(self, domain: str = "evil.com") -> IOCEntry:
        return IOCEntry(
            value=domain,
            ioc_type=IOCType.DOMAIN,
            threat_category=ThreatCategory.PHISHING,
            source="test_feed",
            confidence=80,
            description="Test phishing domain",
        )

    def test_add_and_lookup_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            entry = self._make_ip_entry()
            count = db.add_entries([entry])
            assert count == 1
            result = db.lookup_ip("1.2.3.4")
            assert result is not None
            assert result.value == "1.2.3.4"
            assert result.threat_category == ThreatCategory.C2_SERVER

    def test_add_and_lookup_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            entry = self._make_hash_entry()
            db.add_entries([entry])
            result = db.lookup_hash("a" * 64)
            assert result is not None
            assert result.ioc_type == IOCType.FILE_HASH_SHA256

    def test_add_and_lookup_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            entry = self._make_domain_entry()
            db.add_entries([entry])
            result = db.lookup_domain("evil.com")
            assert result is not None
            assert result.threat_category == ThreatCategory.PHISHING

    def test_lookup_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            assert db.lookup_ip("9.9.9.9") is None
            assert db.lookup_hash("b" * 64) is None
            assert db.lookup_domain("safe.com") is None

    def test_duplicate_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            entry = self._make_ip_entry()
            assert db.add_entries([entry]) == 1
            assert db.add_entries([entry]) == 0  # duplicate

    def test_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            db.add_entries([
                self._make_ip_entry("1.1.1.1"),
                self._make_ip_entry("2.2.2.2"),
                self._make_hash_entry("b" * 64),
                self._make_domain_entry("bad.com"),
            ])
            stats = db.get_stats()
            assert stats["ip_addresses"] == 2
            assert stats["file_hashes"] == 1
            assert stats["domains"] == 1
            assert stats["total"] == 4

    def test_persistence_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            db1 = self._make_db(tmp)
            db1.add_entries([self._make_ip_entry("10.0.0.1")])
            # New db instance from same dir should load persisted data
            db2 = self._make_db(tmp)
            result = db2.lookup_ip("10.0.0.1")
            assert result is not None
            assert result.value == "10.0.0.1"

    def test_needs_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            assert db.needs_refresh("test_feed") is True
            db.mark_refreshed("test_feed")
            assert db.needs_refresh("test_feed") is False

    def test_needs_refresh_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = IOCDatabase(cache_dir=Path(tmp), ttl_seconds=0)
            db.mark_refreshed("test_feed")
            # TTL is 0, so it should need refresh immediately
            assert db.needs_refresh("test_feed") is True

    def test_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            db.add_entries([self._make_ip_entry(), self._make_hash_entry()])
            assert db.get_stats()["total"] == 2
            db.clear()
            assert db.get_stats()["total"] == 0

    def test_url_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            entry = IOCEntry(
                value="http://evil.com/payload.exe",
                ioc_type=IOCType.URL,
                threat_category=ThreatCategory.MALWARE,
                source="test_feed",
                confidence=85,
            )
            db.add_entries([entry])
            result = db.lookup_url("http://evil.com/payload.exe")
            assert result is not None

    def test_case_insensitive_hash_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = self._make_db(tmp)
            db.add_entries([self._make_hash_entry("ABCD" * 16)])
            result = db.lookup_hash("abcd" * 16)
            assert result is not None

    def test_from_dict_round_trip(self):
        entry = self._make_ip_entry()
        d = entry.to_dict()
        restored = IOCEntry.from_dict(d)
        assert restored.value == entry.value
        assert restored.ioc_type == entry.ioc_type
        assert restored.confidence == entry.confidence
