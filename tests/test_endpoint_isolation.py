"""
Tests for the Endpoint Isolation module.

Covers IsolationState dataclass and EndpointIsolationManager.
"""

import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig
from response.actions.endpoint_isolation import (
    EndpointIsolationManager,
    IsolationState,
)


# ---------------------------------------------------------------------------
# TestIsolationState
# ---------------------------------------------------------------------------

class TestIsolationState:
    """Tests for the IsolationState dataclass."""

    def test_state_roundtrip(self):
        """to_dict/from_dict preserves all fields."""
        state = IsolationState(
            isolated=True,
            isolation_time="2026-03-04T10:00:00",
            release_time="2026-03-05T10:00:00",
            timeout_hours=48,
            allowed_ips=["10.0.0.1", "10.0.0.2"],
            mode="partial",
        )

        data = state.to_dict()
        restored = IsolationState.from_dict(data)

        assert restored.isolated == state.isolated
        assert restored.isolation_time == state.isolation_time
        assert restored.release_time == state.release_time
        assert restored.timeout_hours == state.timeout_hours
        assert restored.allowed_ips == state.allowed_ips
        assert restored.mode == state.mode

    def test_default_state(self):
        """Defaults are not isolated."""
        state = IsolationState()

        assert state.isolated is False
        assert state.isolation_time == ""
        assert state.release_time == ""
        assert state.timeout_hours == 24
        assert state.allowed_ips == []
        assert state.mode == "full"


# ---------------------------------------------------------------------------
# TestEndpointIsolationManager
# ---------------------------------------------------------------------------

class TestEndpointIsolationManager:
    """Tests for the endpoint isolation manager."""

    def _make_manager(self, tmpdir: str) -> EndpointIsolationManager:
        """Create a manager with a temporary state file."""
        config = AgentConfig()
        manager = EndpointIsolationManager(config)
        # Override state file to use temp directory
        state_file = Path(tmpdir) / "isolation" / "state.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        manager._state_file = state_file
        return manager

    def test_isolate_and_status(self):
        """Mock subprocess, isolate, verify status shows isolated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                success, msg = manager.isolate(mode="full", timeout_hours=12)

            assert success is True
            assert "isolated" in msg.lower() or "12 hours" in msg

            status = manager.get_isolation_status()
            assert status["isolated"] is True
            assert status["mode"] == "full"
            assert status["timeout_hours"] == 12
            assert "remaining_hours" in status
            assert status["remaining_hours"] > 0

    def test_release(self):
        """Isolate then release, verify not isolated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)

                # Isolate
                success, _ = manager.isolate()
                assert success is True
                assert manager.is_isolated() is True

                # Release
                success, msg = manager.release()
                assert success is True
                assert "released" in msg.lower()

            # Verify state
            status = manager.get_isolation_status()
            assert status["isolated"] is False
            assert status["release_time"] != ""

    def test_double_isolate(self):
        """Isolating twice returns 'already isolated'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)

                # First isolation succeeds
                success1, _ = manager.isolate()
                assert success1 is True

                # Second isolation should fail
                success2, msg2 = manager.isolate()
                assert success2 is False
                assert "already" in msg2.lower()

    def test_release_not_isolated(self):
        """Releasing when not isolated returns error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)

            success, msg = manager.release()
            assert success is False
            assert "not isolated" in msg.lower()

    def test_timeout_auto_release(self):
        """Write state with past timeout, verify is_isolated returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)

            # Write a state that expired 2 hours ago
            expired_time = datetime.now() - timedelta(hours=26)
            state = IsolationState(
                isolated=True,
                isolation_time=expired_time.isoformat(),
                timeout_hours=24,
                mode="full",
            )
            manager._state_file.write_text(json.dumps(state.to_dict(), indent=2))

            # Mock subprocess.run for the auto-release that will be triggered
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                result = manager.is_isolated()

            # Timeout has passed, should auto-release and return False
            assert result is False

    def test_isolation_persists(self):
        """State survives manager recreation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "isolation" / "state.json"
            state_file.parent.mkdir(parents=True, exist_ok=True)

            # Create first manager and isolate
            config = AgentConfig()
            manager1 = EndpointIsolationManager(config)
            manager1._state_file = state_file

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                success, _ = manager1.isolate(timeout_hours=48)
                assert success is True

            # Create second manager pointing to same state file
            manager2 = EndpointIsolationManager(config)
            manager2._state_file = state_file

            assert manager2.is_isolated() is True
            status = manager2.get_isolation_status()
            assert status["isolated"] is True
            assert status["timeout_hours"] == 48

    def test_allowed_ips(self):
        """Verify allowed IPs are included in state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._make_manager(tmpdir)
            allowed = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]

            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                success, _ = manager.isolate(allowed_ips=allowed)

            assert success is True

            status = manager.get_isolation_status()
            assert status["allowed_ips"] == allowed
            assert "10.0.0.1" in status["allowed_ips"]
            assert "10.0.0.2" in status["allowed_ips"]
            assert "192.168.1.100" in status["allowed_ips"]
