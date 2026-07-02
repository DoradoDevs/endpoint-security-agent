"""
Tests for the EDR Event Timeline system.

Covers EDREvent dataclass, EventStore (SQLite), and TimelineQuery.
"""

import sys
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.event_types import EDREvent, EDREventType
from edr.event_store import EventStore
from edr.timeline_query import TimelineQuery


# ---------------------------------------------------------------------------
# TestEDREvent
# ---------------------------------------------------------------------------

class TestEDREvent:
    """Tests for EDREvent dataclass."""

    def test_event_creation(self):
        """Create an event and verify all fields are set correctly."""
        event = EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_process="python.exe",
            target="/usr/bin/python3",
            details={"args": ["--version"]},
            severity="info",
            source_pid=1234,
            correlated_finding_id="finding-001",
        )
        assert event.event_type == EDREventType.PROCESS_START
        assert event.source_process == "python.exe"
        assert event.target == "/usr/bin/python3"
        assert event.details == {"args": ["--version"]}
        assert event.severity == "info"
        assert event.source_pid == 1234
        assert event.correlated_finding_id == "finding-001"
        assert len(event.id) == 12
        assert event.timestamp  # auto-generated, non-empty

    def test_event_roundtrip(self):
        """to_dict and from_dict should preserve all data."""
        original = EDREvent(
            event_type=EDREventType.FILE_CREATE,
            source_process="notepad.exe",
            target="C:\\temp\\notes.txt",
            details={"size": 4096},
            severity="low",
            source_pid=5678,
            correlated_finding_id="finding-abc",
        )
        data = original.to_dict()
        restored = EDREvent.from_dict(data)

        assert restored.id == original.id
        assert restored.timestamp == original.timestamp
        assert restored.event_type == original.event_type
        assert restored.source_process == original.source_process
        assert restored.target == original.target
        assert restored.details == original.details
        assert restored.severity == original.severity
        assert restored.source_pid == original.source_pid
        assert restored.correlated_finding_id == original.correlated_finding_id

    def test_event_auto_id(self):
        """Each event should get a unique auto-generated ID."""
        e1 = EDREvent(event_type=EDREventType.NETWORK_CONNECT)
        e2 = EDREvent(event_type=EDREventType.NETWORK_CONNECT)
        assert e1.id != e2.id
        assert len(e1.id) == 12
        assert len(e2.id) == 12


# ---------------------------------------------------------------------------
# TestEventStore
# ---------------------------------------------------------------------------

class TestEventStore:
    """Tests for SQLite-backed EventStore."""

    def _make_store(self, tmpdir: str) -> EventStore:
        return EventStore(db_path=Path(tmpdir) / "test.db")

    def _make_event(self, **overrides) -> EDREvent:
        defaults = {
            "event_type": EDREventType.PROCESS_START,
            "source_process": "test.exe",
            "target": "/tmp/target",
            "severity": "info",
            "source_pid": 100,
        }
        defaults.update(overrides)
        return EDREvent(**defaults)

    def test_record_and_retrieve(self):
        """Record one event and query it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            event = self._make_event()
            store.record_event(event)

            results = store.get_events(limit=10)
            assert len(results) == 1
            assert results[0].id == event.id
            assert results[0].event_type == EDREventType.PROCESS_START

    def test_record_batch(self):
        """Record 10 events in a batch and verify count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            events = [self._make_event(source_pid=i) for i in range(10)]
            count = store.record_events_batch(events)

            assert count == 10
            assert store.get_total_count() == 10

    def test_get_event_by_id(self):
        """Record then retrieve a single event by its ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            event = self._make_event()
            store.record_event(event)

            retrieved = store.get_event_by_id(event.id)
            assert retrieved is not None
            assert retrieved.id == event.id
            assert retrieved.source_process == event.source_process

            # Non-existent ID
            assert store.get_event_by_id("nonexistent") is None

    def test_get_events_by_pid(self):
        """Filter events by PID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(source_pid=111),
                self._make_event(source_pid=222),
                self._make_event(source_pid=111),
                self._make_event(source_pid=333),
            ])

            results = store.get_events_by_pid(111)
            assert len(results) == 2
            for r in results:
                assert r.source_pid == 111

    def test_get_events_by_process(self):
        """Filter by process name (case-insensitive partial match)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(source_process="Chrome.exe"),
                self._make_event(source_process="chrome_helper"),
                self._make_event(source_process="firefox.exe"),
                self._make_event(source_process="CHROME_RENDERER"),
            ])

            results = store.get_events_by_process("chrome")
            assert len(results) == 3
            for r in results:
                assert "chrome" in r.source_process.lower()

    def test_get_events_by_type(self):
        """Filter by event type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(event_type=EDREventType.PROCESS_START),
                self._make_event(event_type=EDREventType.FILE_CREATE),
                self._make_event(event_type=EDREventType.PROCESS_START),
                self._make_event(event_type=EDREventType.NETWORK_CONNECT),
            ])

            results = store.get_events(event_type=EDREventType.PROCESS_START)
            assert len(results) == 2
            for r in results:
                assert r.event_type == EDREventType.PROCESS_START

    def test_get_events_by_severity(self):
        """Filter by severity level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(severity="info"),
                self._make_event(severity="critical"),
                self._make_event(severity="critical"),
                self._make_event(severity="warning"),
            ])

            results = store.get_events(severity="critical")
            assert len(results) == 2
            for r in results:
                assert r.severity == "critical"

    def test_get_events_since_hours(self):
        """Time-based filter: only events within the last N hours."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            now = datetime.now()

            recent_event = self._make_event(
                source_process="recent.exe",
            )
            recent_event.timestamp = now.isoformat()

            old_event = self._make_event(
                source_process="old.exe",
            )
            old_event.timestamp = (now - timedelta(hours=48)).isoformat()

            store.record_events_batch([recent_event, old_event])

            results = store.get_events(since_hours=24)
            assert len(results) == 1
            assert results[0].source_process == "recent.exe"

    def test_get_event_counts(self):
        """Verify count aggregation by event type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(event_type=EDREventType.PROCESS_START),
                self._make_event(event_type=EDREventType.PROCESS_START),
                self._make_event(event_type=EDREventType.FILE_CREATE),
                self._make_event(event_type=EDREventType.NETWORK_CONNECT),
                self._make_event(event_type=EDREventType.NETWORK_CONNECT),
                self._make_event(event_type=EDREventType.NETWORK_CONNECT),
            ])

            counts = store.get_event_counts(hours=24)
            assert counts["process_start"] == 2
            assert counts["file_create"] == 1
            assert counts["network_connect"] == 3

    def test_purge_old_events(self):
        """Insert old events, purge, and verify they are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            now = datetime.now()

            fresh = self._make_event(source_process="fresh.exe")
            fresh.timestamp = now.isoformat()

            stale = self._make_event(source_process="stale.exe")
            stale.timestamp = (now - timedelta(days=30)).isoformat()

            store.record_events_batch([fresh, stale])
            assert store.get_total_count() == 2

            deleted = store.purge_old_events(retention_days=7)
            assert deleted == 1
            assert store.get_total_count() == 1

            remaining = store.get_events()
            assert remaining[0].source_process == "fresh.exe"

    def test_enforce_size_limit(self):
        """Verify oldest events are deleted when DB exceeds size limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use a tiny size limit to trigger enforcement
            store = EventStore(db_path=Path(tmpdir) / "test.db", max_size_mb=0)

            events = [self._make_event(source_pid=i) for i in range(50)]
            store.record_events_batch(events)
            assert store.get_total_count() == 50

            deleted = store.enforce_size_limit()
            assert deleted > 0
            assert store.get_total_count() < 50

    def test_clear_all(self):
        """Clear all events from the store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([self._make_event() for _ in range(5)])
            assert store.get_total_count() == 5

            cleared = store.clear_all()
            assert cleared == 5
            assert store.get_total_count() == 0

    def test_get_total_count(self):
        """Verify total count accuracy after multiple operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            assert store.get_total_count() == 0

            store.record_event(self._make_event())
            assert store.get_total_count() == 1

            store.record_events_batch([self._make_event() for _ in range(9)])
            assert store.get_total_count() == 10

    def test_thread_safety(self):
        """Record events from multiple threads concurrently and verify count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            errors = []

            def record_batch(thread_id: int):
                try:
                    for i in range(20):
                        event = self._make_event(
                            source_process=f"thread-{thread_id}",
                            source_pid=thread_id * 1000 + i,
                        )
                        store.record_event(event)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=record_batch, args=(t,)) for t in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0, f"Thread errors: {errors}"
            assert store.get_total_count() == 100


# ---------------------------------------------------------------------------
# TestTimelineQuery
# ---------------------------------------------------------------------------

class TestTimelineQuery:
    """Tests for the high-level TimelineQuery interface."""

    def _make_store(self, tmpdir: str) -> EventStore:
        return EventStore(db_path=Path(tmpdir) / "test.db")

    def _make_event(self, **overrides) -> EDREvent:
        defaults = {
            "event_type": EDREventType.PROCESS_START,
            "source_process": "test.exe",
            "target": "/tmp/target",
            "severity": "info",
            "source_pid": 100,
        }
        defaults.update(overrides)
        return EDREvent(**defaults)

    def test_query_events_basic(self):
        """Query with no filters returns all events."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([self._make_event() for _ in range(5)])
            tq = TimelineQuery(store)

            results = tq.query_events()
            assert len(results) == 5

    def test_query_by_process_name(self):
        """Query by process name through the timeline query layer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(source_process="svchost.exe"),
                self._make_event(source_process="svchost.exe"),
                self._make_event(source_process="explorer.exe"),
            ])
            tq = TimelineQuery(store)

            results = tq.query_events(process_name="svchost")
            assert len(results) == 2

    def test_get_process_timeline(self):
        """Get all events for a specific PID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(source_pid=999, event_type=EDREventType.PROCESS_START),
                self._make_event(source_pid=999, event_type=EDREventType.FILE_CREATE),
                self._make_event(source_pid=999, event_type=EDREventType.NETWORK_CONNECT),
                self._make_event(source_pid=888, event_type=EDREventType.PROCESS_START),
            ])
            tq = TimelineQuery(store)

            timeline = tq.get_process_timeline(999)
            assert len(timeline) == 3
            for e in timeline:
                assert e.source_pid == 999

    def test_get_incident_timeline(self):
        """Get events around a correlated finding within a time window."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            now = datetime.now()

            # Create events around the incident
            before = self._make_event(source_process="before.exe")
            before.timestamp = (now - timedelta(minutes=2)).isoformat()

            incident = self._make_event(
                source_process="malware.exe",
                event_type=EDREventType.THREAT_DETECTED,
                severity="critical",
                correlated_finding_id="finding-xyz",
            )
            incident.timestamp = now.isoformat()

            after = self._make_event(source_process="after.exe")
            after.timestamp = (now + timedelta(minutes=1)).isoformat()

            far_away = self._make_event(source_process="far.exe")
            far_away.timestamp = (now - timedelta(hours=2)).isoformat()

            store.record_events_batch([before, incident, after, far_away])
            tq = TimelineQuery(store)

            timeline = tq.get_incident_timeline("finding-xyz", window_minutes=5)
            assert len(timeline) == 3  # before, incident, after (not far_away)

            processes = {e.source_process for e in timeline}
            assert "far.exe" not in processes
            assert "malware.exe" in processes

    def test_get_event_counts(self):
        """Verify counts through the query layer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(event_type=EDREventType.LOGIN_ATTEMPT),
                self._make_event(event_type=EDREventType.LOGIN_ATTEMPT),
                self._make_event(event_type=EDREventType.FILE_MODIFY),
            ])
            tq = TimelineQuery(store)

            counts = tq.get_event_counts(hours=24)
            assert counts["login_attempt"] == 2
            assert counts["file_modify"] == 1

    def test_get_summary(self):
        """Verify summary dict structure and values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(severity="info"),
                self._make_event(severity="critical"),
                self._make_event(severity="critical"),
            ])
            tq = TimelineQuery(store)

            summary = tq.get_summary(hours=24)
            assert "total_events" in summary
            assert summary["total_events"] == 3
            assert "event_type_counts" in summary
            assert "severity_counts" in summary
            assert summary["severity_counts"]["critical"] == 2
            assert summary["severity_counts"]["info"] == 1
            assert "hours_covered" in summary
            assert summary["hours_covered"] == 24
            assert "db_size_mb" in summary

    def test_get_threats(self):
        """Only threat-related events are returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = self._make_store(tmpdir)
            store.record_events_batch([
                self._make_event(event_type=EDREventType.PROCESS_START),
                self._make_event(event_type=EDREventType.THREAT_DETECTED, severity="critical"),
                self._make_event(event_type=EDREventType.RANSOMWARE_ALERT, severity="critical"),
                self._make_event(event_type=EDREventType.FILE_CREATE),
                self._make_event(event_type=EDREventType.PRIVILEGE_ESCALATION, severity="high"),
                self._make_event(event_type=EDREventType.CANARY_TRIGGERED, severity="high"),
                self._make_event(event_type=EDREventType.NETWORK_CONNECT),
            ])
            tq = TimelineQuery(store)

            threats = tq.get_threats(hours=24)
            assert len(threats) == 4

            threat_types = {e.event_type for e in threats}
            assert EDREventType.THREAT_DETECTED in threat_types
            assert EDREventType.RANSOMWARE_ALERT in threat_types
            assert EDREventType.PRIVILEGE_ESCALATION in threat_types
            assert EDREventType.CANARY_TRIGGERED in threat_types
            assert EDREventType.PROCESS_START not in threat_types
            assert EDREventType.FILE_CREATE not in threat_types
