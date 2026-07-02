"""
Tests for the Real-Time Protection Engine.

Covers ProcessMonitor, ConnectionMonitor, and RealTimeProtectionEngine.
"""

import sys
import tempfile
import threading
import time
from collections import namedtuple
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig
from edr.event_types import EDREvent, EDREventType
from edr.event_store import EventStore
from edr.process_monitor import ProcessMonitor
from edr.connection_monitor import ConnectionMonitor, C2_PORTS
from edr.realtime_engine import RealTimeProtectionEngine


# ---------------------------------------------------------------------------
# TestProcessMonitor
# ---------------------------------------------------------------------------

class TestProcessMonitor:
    """Tests for the process creation/termination monitor."""

    def test_snapshot_pids(self):
        """Mock psutil.pids, verify _known_pids populated."""
        config = AgentConfig()
        pm = ProcessMonitor(config)

        mock_pids = [100, 200, 300, 400]
        with patch("psutil.pids", return_value=mock_pids):
            pm._snapshot_pids()

        assert pm._known_pids == {100, 200, 300, 400}

    def test_new_process_detected(self):
        """Add new PID to mock, verify PROCESS_START event fired."""
        config = AgentConfig()
        events_received = []
        pm = ProcessMonitor(config, on_event=lambda e: events_received.append(e))
        pm._known_pids = {100, 200, 300}

        # Mock psutil.pids to return a set that includes a new PID (400)
        MockProcess = MagicMock()
        MockProcess.name.return_value = "new_process.exe"
        MockProcess.exe.return_value = ""
        MockProcess.cmdline.return_value = ["new_process.exe", "--flag"]
        MockProcess.ppid.return_value = 1
        MockProcess.username.return_value = "testuser"
        MockProcess.create_time.return_value = 1700000000.0
        MockProcess.net_connections.return_value = []

        with patch("psutil.pids", return_value=[100, 200, 300, 400]):
            with patch("psutil.Process", return_value=MockProcess):
                pm._check_processes()

        # Should have received a PROCESS_START event for PID 400
        start_events = [e for e in events_received if e.event_type == EDREventType.PROCESS_START]
        assert len(start_events) == 1
        assert start_events[0].source_pid == 400
        assert start_events[0].source_process == "new_process.exe"

    def test_terminated_process_detected(self):
        """Remove PID from mock, verify PROCESS_STOP event."""
        config = AgentConfig()
        events_received = []
        pm = ProcessMonitor(config, on_event=lambda e: events_received.append(e))
        pm._known_pids = {100, 200, 300}

        # PID 300 is gone
        with patch("psutil.pids", return_value=[100, 200]):
            pm._check_processes()

        stop_events = [e for e in events_received if e.event_type == EDREventType.PROCESS_STOP]
        assert len(stop_events) == 1
        assert stop_events[0].source_pid == 300

    def test_suspicious_cmdline_detection(self):
        """Process with 'powershell -enc' raises severity to high."""
        config = AgentConfig()
        events_received = []
        pm = ProcessMonitor(config, on_event=lambda e: events_received.append(e))
        pm._known_pids = {100}

        MockProcess = MagicMock()
        MockProcess.name.return_value = "powershell.exe"
        MockProcess.exe.return_value = ""
        MockProcess.cmdline.return_value = ["powershell", "-enc", "SQBFAFgA"]
        MockProcess.ppid.return_value = 1
        MockProcess.username.return_value = "testuser"
        MockProcess.create_time.return_value = 1700000000.0
        MockProcess.net_connections.return_value = []

        with patch("psutil.pids", return_value=[100, 500]):
            with patch("psutil.Process", return_value=MockProcess):
                pm._check_processes()

        start_events = [e for e in events_received if e.event_type == EDREventType.PROCESS_START]
        assert len(start_events) == 1
        assert start_events[0].severity == "high"
        assert start_events[0].details.get("suspicious_cmdline") is True
        assert start_events[0].details.get("matched_pattern") == "powershell -enc"

    def test_no_psutil_graceful(self):
        """When psutil import fails, no crash."""
        config = AgentConfig()
        pm = ProcessMonitor(config)

        # Simulate psutil not being importable by having _snapshot_pids
        # and _check_processes handle ImportError
        with patch.dict("sys.modules", {"psutil": None}):
            # Should not raise
            pm._snapshot_pids()
            pm._check_processes()

        # _known_pids should remain empty
        assert pm._known_pids == set()


# ---------------------------------------------------------------------------
# TestConnectionMonitor
# ---------------------------------------------------------------------------

class TestConnectionMonitor:
    """Tests for the network connection monitor."""

    def _make_conn(self, pid=1000, local_ip="127.0.0.1", local_port=12345,
                   remote_ip="93.184.216.34", remote_port=443, status="ESTABLISHED"):
        """Create a mock connection object matching psutil's sconn structure."""
        Addr = namedtuple("addr", ["ip", "port"])
        conn = MagicMock()
        conn.pid = pid
        conn.laddr = Addr(ip=local_ip, port=local_port)
        conn.raddr = Addr(ip=remote_ip, port=remote_port)
        conn.status = status
        return conn

    def test_snapshot_connections(self):
        """Mock psutil.net_connections, verify known set populated."""
        config = AgentConfig()
        cm = ConnectionMonitor(config)

        mock_conns = [
            self._make_conn(pid=100, remote_ip="10.0.0.1", remote_port=80),
            self._make_conn(pid=200, remote_ip="10.0.0.2", remote_port=443),
        ]

        with patch("psutil.net_connections", return_value=mock_conns):
            cm._snapshot_connections()

        assert len(cm._known_connections) == 2

    def test_new_connection_detected(self):
        """Add connection to mock, verify event fired."""
        config = AgentConfig()
        events_received = []
        cm = ConnectionMonitor(config, on_event=lambda e: events_received.append(e))

        initial_conn = self._make_conn(pid=100, remote_ip="10.0.0.1", remote_port=80)
        with patch("psutil.net_connections", return_value=[initial_conn]):
            cm._snapshot_connections()

        # Now add a new connection
        new_conn = self._make_conn(pid=200, remote_ip="10.0.0.2", remote_port=443)
        MockProcess = MagicMock()
        MockProcess.name.return_value = "curl"

        with patch("psutil.net_connections", return_value=[initial_conn, new_conn]):
            with patch("psutil.Process", return_value=MockProcess):
                cm._check_connections()

        assert len(events_received) == 1
        assert events_received[0].event_type == EDREventType.NETWORK_CONNECT
        assert events_received[0].source_pid == 200
        assert events_received[0].target == "10.0.0.2:443"

    def test_c2_port_detection(self):
        """Connection to port 4444 raises severity to high."""
        config = AgentConfig()
        events_received = []
        cm = ConnectionMonitor(config, on_event=lambda e: events_received.append(e))
        cm._known_connections = set()  # Start empty

        c2_conn = self._make_conn(pid=300, remote_ip="192.168.1.99", remote_port=4444)
        MockProcess = MagicMock()
        MockProcess.name.return_value = "suspicious.exe"

        with patch("psutil.net_connections", return_value=[c2_conn]):
            with patch("psutil.Process", return_value=MockProcess):
                cm._check_connections()

        assert len(events_received) == 1
        assert events_received[0].severity == "high"
        assert events_received[0].details.get("suspicious_port") is True

    def test_ioc_ip_match(self):
        """Mock IOCDatabase.lookup_ip to return match, verify severity is critical."""
        config = AgentConfig()
        events_received = []

        mock_ioc_entry = MagicMock()
        mock_ioc_entry.threat_category.value = "c2"

        mock_ioc_db = MagicMock()
        mock_ioc_db.lookup_ip.return_value = mock_ioc_entry

        # Pass shared IOC DB via constructor
        cm = ConnectionMonitor(config, on_event=lambda e: events_received.append(e),
                               ioc_db=mock_ioc_db)
        cm._known_connections = set()

        malicious_conn = self._make_conn(pid=400, remote_ip="198.51.100.1", remote_port=8080)
        MockProcess = MagicMock()
        MockProcess.name.return_value = "backdoor.exe"

        with patch("psutil.net_connections", return_value=[malicious_conn]):
            with patch("psutil.Process", return_value=MockProcess):
                cm._check_connections()

        assert len(events_received) == 1
        assert events_received[0].severity == "critical"
        assert events_received[0].details.get("ioc_match") is True
        assert events_received[0].details.get("ioc_category") == "c2"


# ---------------------------------------------------------------------------
# TestRealTimeProtectionEngine
# ---------------------------------------------------------------------------

class TestRealTimeProtectionEngine:
    """Tests for the real-time protection engine orchestrator."""

    def test_engine_init(self):
        """Verify engine creates properly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EventStore(db_path=Path(tmpdir) / "test.db")
            config = AgentConfig()
            engine = RealTimeProtectionEngine(config, event_store=store)

            assert engine.config is config
            assert engine._store is store
            assert engine._event_count == 0
            assert engine._threat_count == 0
            assert engine._threads == []

    def test_start_stop(self):
        """Start engine in thread, stop, verify clean shutdown."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EventStore(db_path=Path(tmpdir) / "test.db")
            config = AgentConfig()
            engine = RealTimeProtectionEngine(config, event_store=store)

            stop_event = threading.Event()

            # Patch out the monitor imports so start() doesn't actually
            # launch real monitors (they would need psutil/watchdog)
            with patch("edr.realtime_engine.RealTimeProtectionEngine._on_process_event"):
                with patch("edr.realtime_engine.RealTimeProtectionEngine._on_connection_event"):
                    t = threading.Thread(target=engine.start, args=(stop_event,), daemon=True)
                    t.start()

                    # Give the engine a moment to start
                    time.sleep(0.5)

                    # Stop the engine
                    engine.stop()
                    t.join(timeout=5)

            assert not t.is_alive()
            assert stop_event.is_set()

    def test_event_recording(self):
        """Fire mock event, verify it is stored in EventStore."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EventStore(db_path=Path(tmpdir) / "test.db")
            config = AgentConfig()
            engine = RealTimeProtectionEngine(config, event_store=store)

            event = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=1234,
                source_process="test.exe",
                severity="info",
            )

            engine._on_process_event(event)

            assert engine._event_count == 1
            stored = store.get_events(limit=10)
            assert len(stored) == 1
            assert stored[0].id == event.id
            assert stored[0].source_process == "test.exe"

    def test_threat_counting(self):
        """Fire high/critical events, verify threat count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EventStore(db_path=Path(tmpdir) / "test.db")
            config = AgentConfig()
            engine = RealTimeProtectionEngine(config, event_store=store)

            # Info event should not increment threat count
            info_event = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=100,
                source_process="normal.exe",
                severity="info",
            )
            engine._on_process_event(info_event)
            assert engine._threat_count == 0

            # High-severity event should increment threat count
            high_event = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=200,
                source_process="suspicious.exe",
                severity="high",
            )
            engine._on_process_event(high_event)
            assert engine._threat_count == 1

            # Critical connection event should also increment
            crit_event = EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_pid=300,
                source_process="malware.exe",
                target="198.51.100.1:4444",
                severity="critical",
            )
            engine._on_connection_event(crit_event)
            assert engine._threat_count == 2

            # Total events should be 3
            assert engine._event_count == 3

            # Verify stats
            stats = engine.get_stats()
            assert stats["total_events"] == 3
            assert stats["total_threats"] == 2
