"""
Tests for the Malware Hash Database.

Covers database creation, hash lookup (SHA-256/SHA-1/MD5), bulk insert,
feed parsing, and statistics.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_intel.hash_database import HashDatabase, HashEntry


class TestHashDatabaseBasic:
    """Basic database operations."""

    def test_create_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            assert db.get_total_count() == 0

    def test_add_and_lookup_sha256(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db.add_hash(
                sha256="a" * 64,
                malware_family="test_malware",
                threat_type="trojan",
                source="test",
            )
            result = db.lookup_sha256("a" * 64)
            assert result is not None
            assert result.malware_family == "test_malware"
            assert result.threat_type == "trojan"

    def test_lookup_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            assert db.lookup_sha256("b" * 64) is None

    def test_add_and_lookup_md5(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db._bulk_insert([HashEntry(
                sha256="c" * 64, md5="d" * 32, source="test",
            )])
            result = db.lookup_md5("d" * 32)
            assert result is not None
            assert result.sha256 == "c" * 64

    def test_add_and_lookup_sha1(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db._bulk_insert([HashEntry(
                sha256="e" * 64, sha1="f" * 40, source="test",
            )])
            result = db.lookup_sha1("f" * 40)
            assert result is not None

    def test_lookup_any_auto_detects_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db._bulk_insert([HashEntry(
                sha256="a" * 64, sha1="b" * 40, md5="c" * 32, source="test",
            )])
            # SHA-256 (64 chars)
            assert db.lookup_any("a" * 64) is not None
            # SHA-1 (40 chars)
            assert db.lookup_any("b" * 40) is not None
            # MD5 (32 chars)
            assert db.lookup_any("c" * 32) is not None
            # Invalid length
            assert db.lookup_any("short") is None


class TestBulkInsert:
    """Test bulk insertion."""

    def test_bulk_insert_multiple(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            entries = [
                HashEntry(sha256=f"{i:064x}", source="test", malware_family=f"malware_{i}")
                for i in range(100)
            ]
            count = db._bulk_insert(entries)
            assert count > 0
            assert db.get_total_count() == 100

    def test_duplicate_insert_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            entry = HashEntry(sha256="a" * 64, source="test")
            db._bulk_insert([entry])
            db._bulk_insert([entry])  # Duplicate
            assert db.get_total_count() == 1


class TestFeedParsing:
    """Test feed CSV parsing."""

    def test_parse_malwarebazaar_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            csv_data = (
                '# MalwareBazaar CSV\n'
                '# first_seen,sha256,md5,sha1,...\n'
                '"2024-01-01","' + 'a' * 64 + '","' + 'b' * 32 + '","' + 'c' * 40 + '",'
                '"reporter","test.exe","exe","application/x-executable","TestMalware","tag1"\n'
            )
            entries = db._parse_malwarebazaar_csv(csv_data)
            assert len(entries) == 1
            assert entries[0].sha256 == "a" * 64
            assert entries[0].md5 == "b" * 32
            assert entries[0].malware_family == "TestMalware"
            assert entries[0].source == "malwarebazaar"

    def test_parse_skips_comments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            csv_data = "# This is a comment\n# Another comment\n"
            entries = db._parse_malwarebazaar_csv(csv_data)
            assert len(entries) == 0


class TestStatistics:
    """Test database statistics."""

    def test_get_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db._bulk_insert([
                HashEntry(sha256="a" * 64, source="malwarebazaar", threat_type="trojan"),
                HashEntry(sha256="b" * 64, source="malwarebazaar", threat_type="ransomware"),
                HashEntry(sha256="c" * 64, source="feodo", threat_type="banking_trojan"),
            ])
            stats = db.get_stats()
            assert stats["total_hashes"] == 3
            assert stats["by_source"]["malwarebazaar"] == 2
            assert stats["by_source"]["feodo"] == 1
            assert "trojan" in stats["by_type"]

    def test_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = HashDatabase(db_path=Path(tmpdir) / "test.db")
            db._set_metadata("test_key", "test_value")
            assert db._get_metadata("test_key") == "test_value"
            assert db._get_metadata("missing") == ""
