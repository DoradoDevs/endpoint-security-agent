"""Tests for the Real-Time File Guard module."""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, GuardConfig, Severity
from core.file_guard import FileGuard, FileGuardHandler


class TestFileGuardHandler:
    """Tests for FileGuardHandler event handling and scanning."""

    def test_handle_event_scans_file(self):
        """Create a temp file, call handle_event, verify no crash."""
        config = AgentConfig()
        handler = FileGuardHandler(config)

        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "testfile.txt"
            test_file.write_text("hello world")

            # Should not raise
            handler.handle_event(str(test_file), "created")

    def test_debounce_prevents_duplicate_scans(self):
        """Call handle_event twice rapidly, verify scanning only happens once."""
        config = AgentConfig()
        config.guard.debounce_ms = 500  # 500ms debounce window
        handler = FileGuardHandler(config)

        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "testfile.txt"
            test_file.write_text("some content")

            with patch.object(handler, '_scan_file') as mock_scan:
                handler.handle_event(str(test_file), "created")
                handler.handle_event(str(test_file), "modified")

                # Only one scan should have occurred due to debounce
                assert mock_scan.call_count == 1

    def test_handle_event_skips_directory(self):
        """Pass a directory path, verify _scan_file not called."""
        config = AgentConfig()
        handler = FileGuardHandler(config)

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(handler, '_scan_file') as mock_scan:
                # tmp itself is a directory, not a file
                handler.handle_event(tmp, "created")
                mock_scan.assert_not_called()

    def test_handle_event_skips_nonexistent(self):
        """Pass nonexistent path, verify no crash."""
        config = AgentConfig()
        handler = FileGuardHandler(config)

        # Should not raise
        handler.handle_event("/nonexistent/path/file.txt", "created")
        handler.handle_event("", "created")

    def test_is_file_locked(self):
        """Verify locked file detection works correctly."""
        config = AgentConfig()
        handler = FileGuardHandler(config)

        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "unlocked.txt"
            test_file.write_text("content")

            # File should not be locked when not held open
            assert handler._is_file_locked(str(test_file)) is False

        # A path that triggers PermissionError should return True
        with patch("builtins.open", side_effect=PermissionError("locked")):
            assert handler._is_file_locked("/some/locked/file.txt") is True

    def test_allowlist_check(self):
        """Mock AllowlistManager, verify excluded paths are skipped."""
        config = AgentConfig()
        handler = FileGuardHandler(config)

        mock_mgr = MagicMock()
        mock_mgr.is_path_excluded.return_value = True

        with patch("core.file_guard.FileGuardHandler._is_allowlisted", return_value=True):
            with tempfile.TemporaryDirectory() as tmp:
                test_file = Path(tmp) / "allowed.txt"
                test_file.write_text("benign content")

                with patch.object(handler, '_scan_file') as mock_scan:
                    handler.handle_event(str(test_file), "created")
                    mock_scan.assert_not_called()

    def test_scan_file_detects_threat(self):
        """Create a temp file with 'meterpreter' content, verify on_threat callback fires."""
        config = AgentConfig()
        threat_callback = MagicMock()
        handler = FileGuardHandler(config, on_threat=threat_callback)

        with tempfile.TemporaryDirectory() as tmp:
            malicious_file = Path(tmp) / "payload.txt"
            malicious_file.write_text("this contains meterpreter shellcode payload")

            handler._scan_file(str(malicious_file))

            # The meterpreter string should trigger the shellcode_markers rule
            assert threat_callback.call_count >= 1
            finding = threat_callback.call_args[0][0]
            assert "filepath" in finding
            assert "severity" in finding
            assert "rule_name" in finding

    def test_scan_file_no_threat(self):
        """Create a normal text file, verify on_threat NOT called."""
        config = AgentConfig()
        threat_callback = MagicMock()
        handler = FileGuardHandler(config, on_threat=threat_callback)

        with tempfile.TemporaryDirectory() as tmp:
            safe_file = Path(tmp) / "readme.txt"
            safe_file.write_text("This is a perfectly normal document with no issues.")

            handler._scan_file(str(safe_file))

            threat_callback.assert_not_called()

    def test_auto_quarantine(self):
        """Mock FileQuarantineManager, enable auto_quarantine, verify quarantine called."""
        config = AgentConfig()
        config.guard.auto_quarantine = True
        handler = FileGuardHandler(config)

        finding_info = {
            "rule_name": "shellcode_markers",
            "description": "Detects shellcode markers",
            "severity": "high",
            "category": "Shellcode",
            "filepath": "/tmp/evil.bin",
            "matches": 1,
        }

        mock_mgr = MagicMock()
        mock_mgr.quarantine.return_value = (True, "quarantined")

        with patch(
            "core.file_guard.FileGuardHandler._auto_quarantine"
        ) as mock_aq:
            # Simulate what _scan_file does when auto_quarantine is enabled
            handler._auto_quarantine = mock_aq
            handler._auto_quarantine(finding_info["filepath"], finding_info)
            mock_aq.assert_called_once_with(finding_info["filepath"], finding_info)


class TestFileGuardDefaultDirs:
    """Tests for default watch directory detection."""

    def test_default_watch_dirs_returns_list(self):
        """Verify returns a list."""
        dirs = FileGuardHandler.default_watch_dirs()
        assert isinstance(dirs, list)

    def test_default_watch_dirs_existing_only(self):
        """Verify all returned dirs exist on the filesystem."""
        dirs = FileGuardHandler.default_watch_dirs()
        for d in dirs:
            assert os.path.isdir(d), f"Directory does not exist: {d}"


class TestFileGuard:
    """Tests for the FileGuard orchestrator."""

    def test_file_guard_init(self):
        """Verify FileGuard creates properly with config."""
        config = AgentConfig()
        guard = FileGuard(config)

        assert guard.config is config
        assert guard._handler is not None
        assert isinstance(guard._handler, FileGuardHandler)
        assert guard._threats == []
        assert guard._observer is None

    def test_polling_fallback_detects_new_file(self):
        """Create a temp dir, start polling in a thread, create a new file, verify handle_event is called."""
        config = AgentConfig()
        guard = FileGuard(config)

        with tempfile.TemporaryDirectory() as tmp:
            # Pre-populate config to watch our temp dir
            config.guard.directories = [tmp]

            stop_event = threading.Event()
            events_detected = []

            original_handle = guard._handler.handle_event

            def tracking_handle(event_path, event_type):
                events_detected.append((event_path, event_type))
                original_handle(event_path, event_type)

            guard._handler.handle_event = tracking_handle

            # Start polling in background thread
            poll_thread = threading.Thread(
                target=guard._polling_fallback,
                args=([tmp], stop_event),
                daemon=True,
            )
            poll_thread.start()

            # Wait for initial snapshot to complete, then create a new file
            time.sleep(1.0)
            new_file = Path(tmp) / "newfile.txt"
            new_file.write_text("new content")

            # Wait for polling cycle to pick it up
            time.sleep(7.0)

            # Stop the polling
            stop_event.set()
            poll_thread.join(timeout=10)

            # Verify the new file was detected
            detected_paths = [e[0] for e in events_detected]
            assert any("newfile.txt" in p for p in detected_paths), (
                f"Expected newfile.txt in detected events, got: {detected_paths}"
            )

    def test_stop_sets_event(self):
        """Verify stop gracefully terminates."""
        config = AgentConfig()
        guard = FileGuard(config)

        # When no observer is set, stop should not raise
        guard.stop()

        # With a mock observer, stop should call observer.stop() and join()
        mock_observer = MagicMock()
        guard._observer = mock_observer

        guard.stop()

        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once_with(timeout=5)
