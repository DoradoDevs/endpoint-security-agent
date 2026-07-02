"""Tests for the Sentinel allowlist / exclusion manager.

Covers:
  - AllowlistEntry: serialisation round-trip
  - AllowlistManager: add / remove / list / query operations
  - Per-scanner scoping
  - Glob and path matching (cross-platform)
  - Persistence across manager instances
  - Concurrent additions from different scopes
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# Ensure project root is importable
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from core.allowlist import AllowlistEntry, AllowlistManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Provide a fresh temporary directory for allowlist storage."""
    d = tmp_path / "allowlist"
    d.mkdir()
    return d


@pytest.fixture
def manager(data_dir: Path) -> AllowlistManager:
    """Provide an AllowlistManager writing to a temp directory."""
    return AllowlistManager(data_dir=data_dir)


# ---------------------------------------------------------------------------
# AllowlistEntry tests
# ---------------------------------------------------------------------------

class TestAllowlistEntry:
    """Tests for AllowlistEntry serialisation."""

    def test_to_dict_from_dict_roundtrip(self) -> None:
        entry = AllowlistEntry(
            id="abcd1234",
            entry_type="hash",
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            scanner_scope=["MalwareScanner", "IOCScanner"],
            reason="Known safe binary",
            added_timestamp="2025-06-15T12:00:00+00:00",
            added_by="cli",
        )
        d = entry.to_dict()
        restored = AllowlistEntry.from_dict(d)

        assert restored.id == entry.id
        assert restored.entry_type == entry.entry_type
        assert restored.value == entry.value
        assert restored.scanner_scope == entry.scanner_scope
        assert restored.reason == entry.reason
        assert restored.added_timestamp == entry.added_timestamp
        assert restored.added_by == entry.added_by

    def test_from_dict_missing_optional_fields(self) -> None:
        """Missing optional keys should fall back to defaults."""
        d = {"id": "abc12345", "entry_type": "path", "value": "/tmp/*.log"}
        entry = AllowlistEntry.from_dict(d)
        assert entry.scanner_scope == []
        assert entry.reason == ""
        assert entry.added_by == "cli"


# ---------------------------------------------------------------------------
# AllowlistManager — add / remove / list
# ---------------------------------------------------------------------------

class TestAllowlistManager:
    """Core AllowlistManager operations."""

    # -- Add entries -------------------------------------------------------

    def test_add_hash_entry(self, manager: AllowlistManager) -> None:
        entry = manager.add_hash(
            "AABB1122CCDD3344EEFF5566AABB1122CCDD3344EEFF5566AABB1122CCDD3344",
            reason="Test hash",
        )
        assert entry.entry_type == "hash"
        # Value should be stored lowercase
        assert entry.value == entry.value.lower()
        assert len(entry.id) == 8
        assert entry.added_by == "cli"
        assert entry.reason == "Test hash"
        assert entry.added_timestamp != ""

    def test_add_path_entry(self, manager: AllowlistManager) -> None:
        entry = manager.add_path("/var/log/*.log", reason="Log files")
        assert entry.entry_type == "path"
        assert entry.value == "/var/log/*.log"
        assert entry.reason == "Log files"

    def test_add_process_entry(self, manager: AllowlistManager) -> None:
        entry = manager.add_process("svchost.exe", reason="System process")
        assert entry.entry_type == "process"
        assert entry.value == "svchost.exe"
        assert entry.reason == "System process"

    def test_add_entry_default_reason(self, manager: AllowlistManager) -> None:
        """When no reason is given, a sensible default is used."""
        entry = manager.add_hash("aa" * 32)
        assert "Allowlisted" in entry.reason

    def test_add_entry_custom_added_by(self, manager: AllowlistManager) -> None:
        entry = manager.add_hash("bb" * 32, added_by="rollback")
        assert entry.added_by == "rollback"

    # -- Remove entries ----------------------------------------------------

    def test_remove_entry(self, manager: AllowlistManager) -> None:
        entry = manager.add_hash("cc" * 32)
        success, msg = manager.remove(entry.id)
        assert success is True
        assert entry.value in msg

        # Verify it's actually gone
        entries = manager.list_entries()
        assert len(entries) == 0

    def test_remove_nonexistent(self, manager: AllowlistManager) -> None:
        success, msg = manager.remove("zzzzzzzz")
        assert success is False
        assert "not found" in msg.lower()

    # -- List entries ------------------------------------------------------

    def test_list_entries_all(self, manager: AllowlistManager) -> None:
        manager.add_hash("aa" * 32)
        manager.add_path("/tmp/*")
        manager.add_process("python")
        entries = manager.list_entries()
        assert len(entries) == 3

    def test_list_entries_by_type(self, manager: AllowlistManager) -> None:
        manager.add_hash("aa" * 32)
        manager.add_hash("bb" * 32)
        manager.add_path("/tmp/*")
        manager.add_process("python")

        hash_entries = manager.list_entries(entry_type="hash")
        assert len(hash_entries) == 2
        assert all(e.entry_type == "hash" for e in hash_entries)

        path_entries = manager.list_entries(entry_type="path")
        assert len(path_entries) == 1

        process_entries = manager.list_entries(entry_type="process")
        assert len(process_entries) == 1


# ---------------------------------------------------------------------------
# AllowlistManager — hash queries
# ---------------------------------------------------------------------------

class TestHashAllowlist:
    """Tests for is_hash_allowed."""

    def test_is_hash_allowed_exact(self, manager: AllowlistManager) -> None:
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        manager.add_hash(sha)
        assert manager.is_hash_allowed(sha) is True

    def test_is_hash_allowed_case_insensitive(self, manager: AllowlistManager) -> None:
        sha_lower = "abcdef1234567890" * 4
        manager.add_hash(sha_lower)
        assert manager.is_hash_allowed(sha_lower.upper()) is True

    def test_is_hash_allowed_not_present(self, manager: AllowlistManager) -> None:
        assert manager.is_hash_allowed("ff" * 32) is False

    def test_is_hash_allowed_with_scanner_scope(self, manager: AllowlistManager) -> None:
        """A scoped hash should only be allowed for the listed scanners."""
        sha = "dd" * 32
        manager.add_hash(sha, scanner_scope=["MalwareScanner"])

        # Allowed for MalwareScanner
        assert manager.is_hash_allowed(sha, scanner_name="MalwareScanner") is True
        # NOT allowed for IOCScanner
        assert manager.is_hash_allowed(sha, scanner_name="IOCScanner") is False


# ---------------------------------------------------------------------------
# AllowlistManager — path queries
# ---------------------------------------------------------------------------

class TestPathExclusion:
    """Tests for is_path_excluded and glob matching."""

    def test_is_path_excluded_exact(self, manager: AllowlistManager) -> None:
        manager.add_path("/var/log/syslog")
        assert manager.is_path_excluded("/var/log/syslog") is True
        assert manager.is_path_excluded("/var/log/other") is False

    def test_is_path_excluded_glob_star(self, manager: AllowlistManager) -> None:
        manager.add_path("/var/log/*.log")
        assert manager.is_path_excluded("/var/log/app.log") is True
        assert manager.is_path_excluded("/var/log/error.log") is True
        assert manager.is_path_excluded("/var/log/app.txt") is False

    def test_is_path_excluded_glob_doublestar(self, manager: AllowlistManager) -> None:
        manager.add_path("/home/user/**/*.tmp")
        assert manager.is_path_excluded("/home/user/docs/file.tmp") is True
        assert manager.is_path_excluded("/home/user/deep/nested/file.tmp") is True
        assert manager.is_path_excluded("/home/user/file.tmp") is True
        assert manager.is_path_excluded("/home/user/docs/file.log") is False

    def test_is_path_excluded_windows_paths(self, manager: AllowlistManager) -> None:
        """Windows backslash paths should be normalised to forward slashes."""
        manager.add_path("C:/Users/*/AppData/*.tmp")
        assert manager.is_path_excluded("C:\\Users\\Admin\\AppData\\cache.tmp") is True
        assert manager.is_path_excluded("C:/Users/Admin/AppData/cache.tmp") is True

    def test_is_path_excluded_unix_paths(self, manager: AllowlistManager) -> None:
        manager.add_path("/opt/sentinel/cache/*")
        assert manager.is_path_excluded("/opt/sentinel/cache/data.bin") is True
        assert manager.is_path_excluded("/opt/sentinel/logs/data.bin") is False

    def test_is_path_excluded_doublestar_prefix(self, manager: AllowlistManager) -> None:
        """A leading ** should match the filename regardless of directory."""
        manager.add_path("**/*.log")
        assert manager.is_path_excluded("/any/deep/path/app.log") is True
        assert manager.is_path_excluded("C:\\Logs\\error.log") is True
        assert manager.is_path_excluded("/root/file.txt") is False


# ---------------------------------------------------------------------------
# AllowlistManager — process queries
# ---------------------------------------------------------------------------

class TestProcessExclusion:
    """Tests for is_process_excluded."""

    def test_is_process_excluded(self, manager: AllowlistManager) -> None:
        manager.add_process("svchost.exe")
        assert manager.is_process_excluded("svchost.exe") is True
        assert manager.is_process_excluded("explorer.exe") is False

    def test_is_process_excluded_case_insensitive(self, manager: AllowlistManager) -> None:
        manager.add_process("Python.exe")
        assert manager.is_process_excluded("python.exe") is True
        assert manager.is_process_excluded("PYTHON.EXE") is True


# ---------------------------------------------------------------------------
# Scanner scope
# ---------------------------------------------------------------------------

class TestScannerScope:
    """Tests for per-scanner scoping logic."""

    def test_empty_allowlist_blocks_nothing(self, manager: AllowlistManager) -> None:
        """An empty allowlist should not exclude anything."""
        assert manager.is_hash_allowed("aa" * 32) is False
        assert manager.is_path_excluded("/any/path") is False
        assert manager.is_process_excluded("any.exe") is False

    def test_scanner_scope_empty_applies_all(self, manager: AllowlistManager) -> None:
        """An entry with no scanner_scope applies to every scanner."""
        sha = "ee" * 32
        manager.add_hash(sha, scanner_scope=None)

        assert manager.is_hash_allowed(sha, scanner_name="MalwareScanner") is True
        assert manager.is_hash_allowed(sha, scanner_name="IOCScanner") is True
        assert manager.is_hash_allowed(sha, scanner_name="AnyScanner") is True

    def test_scanner_scope_specific_scanner(self, manager: AllowlistManager) -> None:
        """An entry scoped to specific scanners should only apply to those."""
        manager.add_process("agent.exe", scanner_scope=["MalwareScanner", "HeuristicScanner"])

        assert manager.is_process_excluded("agent.exe", scanner_name="MalwareScanner") is True
        assert manager.is_process_excluded("agent.exe", scanner_name="HeuristicScanner") is True
        assert manager.is_process_excluded("agent.exe", scanner_name="IOCScanner") is False

    def test_scanner_scope_no_scanner_name_provided(self, manager: AllowlistManager) -> None:
        """When no scanner_name is given, scoped entries still match (permissive)."""
        sha = "ff" * 32
        manager.add_hash(sha, scanner_scope=["MalwareScanner"])
        # No scanner_name provided — should still be considered allowed
        assert manager.is_hash_allowed(sha) is True


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    """Tests for file-based persistence."""

    def test_persistence_roundtrip(self) -> None:
        """Entries survive across AllowlistManager instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            mgr1 = AllowlistManager(data_dir=data_dir)
            mgr1.add_hash("aa" * 32, reason="Persist test")
            mgr1.add_path("/tmp/*.log")
            mgr1.add_process("daemon")

            # Create a brand-new manager pointing at the same directory
            mgr2 = AllowlistManager(data_dir=data_dir)
            entries = mgr2.list_entries()
            assert len(entries) == 3

            types = {e.entry_type for e in entries}
            assert types == {"hash", "path", "process"}

            # Verify query still works
            assert mgr2.is_hash_allowed("aa" * 32) is True
            assert mgr2.is_path_excluded("/tmp/app.log") is True
            assert mgr2.is_process_excluded("daemon") is True

    def test_allowlist_file_is_valid_json(self, manager: AllowlistManager) -> None:
        """The on-disk file should always be valid JSON."""
        manager.add_hash("ab" * 32)
        import json
        raw = manager.allowlist_file.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert isinstance(data, dict)
        assert len(data) == 1


# ---------------------------------------------------------------------------
# Concurrent / multi-scope additions
# ---------------------------------------------------------------------------

class TestConcurrentAdd:
    """Tests for adding entries from multiple sources."""

    def test_concurrent_add(self) -> None:
        """Adding from two different scopes should preserve both entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            mgr = AllowlistManager(data_dir=data_dir)
            e1 = mgr.add_hash("11" * 32, added_by="cli")
            e2 = mgr.add_hash("22" * 32, added_by="cleanup_wizard")

            entries = mgr.list_entries()
            assert len(entries) == 2

            ids = {e.id for e in entries}
            assert e1.id in ids
            assert e2.id in ids

            sources = {e.added_by for e in entries}
            assert "cli" in sources
            assert "cleanup_wizard" in sources

    def test_add_multiple_types_same_manager(self, manager: AllowlistManager) -> None:
        """Mixing entry types in the same manager works correctly."""
        manager.add_hash("aa" * 32, scanner_scope=["MalwareScanner"])
        manager.add_path("/opt/**/*.bin", scanner_scope=["IOCScanner"])
        manager.add_process("httpd", scanner_scope=["HeuristicScanner"])

        assert manager.is_hash_allowed("aa" * 32, scanner_name="MalwareScanner") is True
        assert manager.is_hash_allowed("aa" * 32, scanner_name="IOCScanner") is False

        assert manager.is_path_excluded("/opt/data/file.bin", scanner_name="IOCScanner") is True
        assert manager.is_path_excluded("/opt/data/file.bin", scanner_name="MalwareScanner") is False

        assert manager.is_process_excluded("httpd", scanner_name="HeuristicScanner") is True
        assert manager.is_process_excluded("httpd", scanner_name="MalwareScanner") is False
