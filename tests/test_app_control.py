"""Tests for Application Control module."""

import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.app_control import ApplicationControl, WhitelistEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_controller(tmp_dir: str, mode: str = "disabled") -> ApplicationControl:
    """Create an ApplicationControl with a temp whitelist path."""
    wl_path = Path(tmp_dir) / "whitelist.json"
    ctrl = ApplicationControl(whitelist_path=wl_path)
    ctrl.set_mode(mode)
    return ctrl


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_disabled_mode_allows_all():
    """Disabled mode always returns allowed=True."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="disabled")

        result = ctrl.check_process("malware.exe")

        assert result["allowed"] is True
        assert result["mode"] == "disabled"


def test_disabled_mode_allows_unknown():
    """Even a completely unknown process is allowed in disabled mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="disabled")

        result = ctrl.check_process("totally_unknown_thing.exe")
        assert result["allowed"] is True


def test_learning_mode_adds_to_whitelist():
    """New process is auto-added in learning mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="learning")
        initial_count = ctrl.get_whitelist_count()

        result = ctrl.check_process("new_app.exe", exe_path="/usr/bin/new_app")

        assert result["allowed"] is True
        assert ctrl.get_whitelist_count() == initial_count + 1
        # Check it was added with "learning" source
        entries = ctrl.get_whitelist()
        names = [e.exe_name for e in entries]
        assert "new_app.exe" in names
        entry = [e for e in entries if e.exe_name == "new_app.exe"][0]
        assert entry.added_by == "learning"


def test_learning_mode_does_not_duplicate():
    """Checking the same process twice in learning mode does not duplicate."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="learning")

        ctrl.check_process("new_app.exe")
        count_after_first = ctrl.get_whitelist_count()

        ctrl.check_process("new_app.exe")
        count_after_second = ctrl.get_whitelist_count()

        assert count_after_first == count_after_second


def test_alert_mode_flags_unknown():
    """Unknown process flagged with action=alert in alert mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")

        result = ctrl.check_process("suspicious.exe")

        assert result["allowed"] is False
        assert result["action"] == "alert"
        assert "suspicious.exe" in result["reason"]


def test_alert_mode_allows_whitelisted():
    """Whitelisted process is allowed in alert mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")
        # explorer.exe is in the system whitelist
        result = ctrl.check_process("explorer.exe")

        assert result["allowed"] is True


def test_enforce_mode_kills():
    """Verify kill called for non-whitelisted process in enforce mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="enforce")

        with patch.object(ctrl, "_kill_process_by_name") as mock_kill:
            result = ctrl.check_process("bad_process.exe")

        assert result["allowed"] is False
        assert result["action"] == "killed"
        mock_kill.assert_called_once_with("bad_process.exe")


def test_enforce_mode_allows_whitelisted():
    """Whitelisted process is not killed in enforce mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="enforce")

        result = ctrl.check_process("explorer.exe")
        assert result["allowed"] is True
        assert "action" not in result


def test_manual_add_remove():
    """Add and remove from whitelist manually."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp)

        entry = ctrl.add_to_whitelist("custom_app.exe", exe_path="/opt/custom", exe_hash="abc123")

        assert entry.exe_name == "custom_app.exe"
        assert entry.exe_hash == "abc123"
        assert entry.added_by == "manual"
        assert ctrl._is_whitelisted("custom_app.exe")

        removed = ctrl.remove_from_whitelist("custom_app.exe")
        assert removed is True
        assert not ctrl._is_whitelisted("custom_app.exe")

        # Removing again returns False
        removed_again = ctrl.remove_from_whitelist("custom_app.exe")
        assert removed_again is False


def test_system_whitelist_populated():
    """Fresh manager has system processes in whitelist."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp)

        assert ctrl.get_whitelist_count() > 0
        names = [e.exe_name.lower() for e in ctrl.get_whitelist()]
        assert "explorer.exe" in names
        assert "python.exe" in names
        assert "bash" in names


def test_whitelist_persistence():
    """Save and load whitelist across instances."""
    with tempfile.TemporaryDirectory() as tmp:
        wl_path = Path(tmp) / "whitelist.json"

        # First instance — add a custom entry
        ctrl1 = ApplicationControl(whitelist_path=wl_path)
        ctrl1.add_to_whitelist("persistent_app.exe", exe_hash="hash999")

        # Second instance — load from same path
        ctrl2 = ApplicationControl(whitelist_path=wl_path)

        assert ctrl2._is_whitelisted("persistent_app.exe")
        entries = ctrl2.get_whitelist()
        match = [e for e in entries if e.exe_name == "persistent_app.exe"]
        assert len(match) == 1
        assert match[0].exe_hash == "hash999"


def test_whitelist_entry_roundtrip():
    """WhitelistEntry to_dict/from_dict roundtrip."""
    entry = WhitelistEntry(
        exe_hash="sha256abc",
        exe_path="/usr/bin/app",
        exe_name="app",
        added_by="manual",
        trusted=True,
    )
    data = entry.to_dict()
    restored = WhitelistEntry.from_dict(data)

    assert restored.exe_hash == "sha256abc"
    assert restored.exe_path == "/usr/bin/app"
    assert restored.exe_name == "app"
    assert restored.added_by == "manual"
    assert restored.trusted is True


def test_check_by_hash():
    """Whitelist entry matched by hash even if name differs."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")
        ctrl.add_to_whitelist("original_name.exe", exe_hash="unique_hash_123")

        # Check with a different name but same hash
        result = ctrl.check_process("renamed.exe", exe_hash="unique_hash_123")

        assert result["allowed"] is True


def test_check_by_hash_no_match():
    """Wrong hash does not match."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")
        ctrl.add_to_whitelist("app.exe", exe_hash="correct_hash")

        result = ctrl.check_process("unknown.exe", exe_hash="wrong_hash")

        assert result["allowed"] is False


def test_get_status():
    """Status dict has expected keys."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")

        status = ctrl.get_status()

        assert "mode" in status
        assert status["mode"] == "alert"
        assert "whitelist_count" in status
        assert isinstance(status["whitelist_count"], int)
        assert "whitelist_path" in status
        assert isinstance(status["whitelist_path"], str)


def test_set_mode_invalid():
    """Setting an invalid mode does not change the current mode."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")

        ctrl.set_mode("invalid_mode")

        assert ctrl.get_mode() == "alert"


def test_get_whitelist_returns_list():
    """get_whitelist returns a list of WhitelistEntry objects."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp)

        wl = ctrl.get_whitelist()

        assert isinstance(wl, list)
        assert all(isinstance(e, WhitelistEntry) for e in wl)


def test_case_insensitive_lookup():
    """Whitelist lookup is case-insensitive."""
    with tempfile.TemporaryDirectory() as tmp:
        ctrl = _make_controller(tmp, mode="alert")
        ctrl.add_to_whitelist("MyApp.exe")

        result = ctrl.check_process("myapp.exe")
        assert result["allowed"] is True

        result2 = ctrl.check_process("MYAPP.EXE")
        assert result2["allowed"] is True


if __name__ == "__main__":
    test_disabled_mode_allows_all()
    test_disabled_mode_allows_unknown()
    test_learning_mode_adds_to_whitelist()
    test_learning_mode_does_not_duplicate()
    test_alert_mode_flags_unknown()
    test_alert_mode_allows_whitelisted()
    test_enforce_mode_kills()
    test_enforce_mode_allows_whitelisted()
    test_manual_add_remove()
    test_system_whitelist_populated()
    test_whitelist_persistence()
    test_whitelist_entry_roundtrip()
    test_check_by_hash()
    test_check_by_hash_no_match()
    test_get_status()
    test_set_mode_invalid()
    test_get_whitelist_returns_list()
    test_case_insensitive_lookup()
    print("All app control tests passed!")
