"""
Tests for the EDR Event Correlation Engine.

Covers CorrelationEngine, CorrelatedAlert, built-in rules, deduplication,
and thread-safety.
"""

import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.event_types import EDREvent, EDREventType
from edr.correlation_engine import (
    AlertSeverity,
    CorrelatedAlert,
    CorrelationEngine,
    CorrelationRule,
    BUILTIN_RULES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    event_type: EDREventType,
    pid: int = 1000,
    process: str = "test.exe",
    target: str = "",
    severity: str = "info",
    details: dict | None = None,
) -> EDREvent:
    """Create a test EDR event with defaults."""
    return EDREvent(
        event_type=event_type,
        source_pid=pid,
        source_process=process,
        target=target,
        severity=severity,
        details=details or {},
    )


# ---------------------------------------------------------------------------
# TestCorrelatedAlert
# ---------------------------------------------------------------------------

class TestCorrelatedAlert:
    """Tests for the CorrelatedAlert dataclass."""

    def test_creation(self):
        alert = CorrelatedAlert(
            rule_name="TestRule",
            description="A test alert",
            severity=AlertSeverity.HIGH,
        )
        assert alert.rule_name == "TestRule"
        assert alert.severity == AlertSeverity.HIGH
        assert len(alert.id) == 12

    def test_to_dict(self):
        event = _make_event(EDREventType.PROCESS_START)
        alert = CorrelatedAlert(
            rule_name="TestRule",
            description="desc",
            severity=AlertSeverity.CRITICAL,
            mitre_tactic="Execution",
            mitre_technique="T1059",
            events=[event],
            source_pids=[1000],
            evidence={"key": "value"},
        )
        d = alert.to_dict()
        assert d["rule_name"] == "TestRule"
        assert d["severity"] == "critical"
        assert d["event_count"] == 1
        assert d["evidence"]["key"] == "value"
        assert d["mitre_technique"] == "T1059"


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Basic
# ---------------------------------------------------------------------------

class TestCorrelationEngineBasic:
    """Basic engine tests without built-in rules."""

    def test_empty_ingest(self):
        """Ingesting events with no rules produces no alerts."""
        engine = CorrelationEngine(rules=[])
        event = _make_event(EDREventType.PROCESS_START)
        alerts = engine.ingest(event)
        assert alerts == []

    def test_simple_rule_triggers(self):
        """A rule with min_events=2 triggers after two matching events."""
        rule = CorrelationRule(
            name="Two Processes",
            description="Two process starts within window",
            required_event_types={EDREventType.PROCESS_START},
            min_events=2,
            window_seconds=60,
            severity=AlertSeverity.MEDIUM,
            group_by="pid",
        )
        engine = CorrelationEngine(rules=[rule])

        # First event — not enough
        e1 = _make_event(EDREventType.PROCESS_START, pid=100)
        alerts = engine.ingest(e1)
        assert len(alerts) == 0

        # Second event — triggers
        e2 = _make_event(EDREventType.PROCESS_START, pid=100)
        alerts = engine.ingest(e2)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "Two Processes"
        assert alerts[0].severity == AlertSeverity.MEDIUM

    def test_required_types_must_all_appear(self):
        """Rule requires both PROCESS_START and NETWORK_CONNECT."""
        rule = CorrelationRule(
            name="Process + Network",
            description="Process start followed by network connect",
            required_event_types={EDREventType.PROCESS_START, EDREventType.NETWORK_CONNECT},
            min_events=2,
            window_seconds=60,
            group_by="pid",
        )
        engine = CorrelationEngine(rules=[rule])

        # Two process starts — does NOT trigger (missing NETWORK_CONNECT)
        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=200))
        alerts = engine.ingest(_make_event(EDREventType.PROCESS_START, pid=200))
        assert len(alerts) == 0

        # Add a network event — triggers
        alerts = engine.ingest(_make_event(EDREventType.NETWORK_CONNECT, pid=200,
                                           details={"remote_ip": "10.0.0.1"}))
        assert len(alerts) == 1

    def test_global_grouping(self):
        """Rules with group_by='global' correlate across PIDs."""
        rule = CorrelationRule(
            name="Global Rule",
            description="Any two events globally",
            required_event_types={EDREventType.PROCESS_START},
            min_events=2,
            window_seconds=60,
            group_by="global",
        )
        engine = CorrelationEngine(rules=[rule])

        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=100))
        alerts = engine.ingest(_make_event(EDREventType.PROCESS_START, pid=200))
        assert len(alerts) == 1

    def test_ip_grouping(self):
        """Rules with group_by='ip' correlate by remote IP."""
        rule = CorrelationRule(
            name="IP Rule",
            description="Multiple connections to same IP",
            required_event_types={EDREventType.NETWORK_CONNECT},
            min_events=2,
            window_seconds=60,
            group_by="ip",
        )
        engine = CorrelationEngine(rules=[rule])

        engine.ingest(_make_event(
            EDREventType.NETWORK_CONNECT, pid=100,
            details={"remote_ip": "192.168.1.1"},
        ))
        alerts = engine.ingest(_make_event(
            EDREventType.NETWORK_CONNECT, pid=200,
            details={"remote_ip": "192.168.1.1"},
        ))
        assert len(alerts) == 1

        # Different IP — should NOT trigger (separate window)
        alerts = engine.ingest(_make_event(
            EDREventType.NETWORK_CONNECT, pid=300,
            details={"remote_ip": "10.0.0.1"},
        ))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    """Tests for alert deduplication."""

    def test_duplicate_suppressed(self):
        """Same rule + context should not fire twice within dedup window."""
        rule = CorrelationRule(
            name="Dedup Test",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=2,
            window_seconds=60,
            group_by="pid",
        )
        engine = CorrelationEngine(rules=[rule], dedup_window_seconds=300)

        # Trigger first alert
        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=500))
        alerts1 = engine.ingest(_make_event(EDREventType.PROCESS_START, pid=500))
        assert len(alerts1) == 1

        # Third event — should be suppressed (dedup)
        alerts2 = engine.ingest(_make_event(EDREventType.PROCESS_START, pid=500))
        assert len(alerts2) == 0

    def test_different_pids_not_deduped(self):
        """Same rule but different PIDs should both fire."""
        rule = CorrelationRule(
            name="PID Dedup",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=2,
            window_seconds=60,
            group_by="pid",
        )
        engine = CorrelationEngine(rules=[rule])

        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=100))
        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=100))

        engine.ingest(_make_event(EDREventType.PROCESS_START, pid=200))
        alerts = engine.ingest(_make_event(EDREventType.PROCESS_START, pid=200))
        assert len(alerts) == 1  # PID 200 should fire independently


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Custom Conditions
# ---------------------------------------------------------------------------

class TestCustomConditions:
    """Tests for rules with custom condition functions."""

    def test_condition_rejects(self):
        """Custom condition returns False — no alert."""
        def always_false(events):
            return False, {}

        rule = CorrelationRule(
            name="Rejected",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=1,
            window_seconds=60,
            condition=always_false,
            group_by="global",
        )
        engine = CorrelationEngine(rules=[rule])
        alerts = engine.ingest(_make_event(EDREventType.PROCESS_START))
        assert len(alerts) == 0

    def test_condition_accepts_with_evidence(self):
        """Custom condition returns True with evidence — alert includes it."""
        def always_true(events):
            return True, {"found": "malware"}

        rule = CorrelationRule(
            name="Accepted",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=1,
            window_seconds=60,
            condition=always_true,
            group_by="global",
        )
        engine = CorrelationEngine(rules=[rule])
        alerts = engine.ingest(_make_event(EDREventType.PROCESS_START))
        assert len(alerts) == 1
        assert alerts[0].evidence["found"] == "malware"


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Built-in Rules
# ---------------------------------------------------------------------------

class TestBuiltinRules:
    """Tests for built-in correlation rule detection patterns."""

    def test_c2_beacon_rule(self):
        """Temp-dir process + outbound connection triggers C2 alert."""
        engine = CorrelationEngine()  # Uses BUILTIN_RULES

        # Process starts from temp directory
        engine.ingest(_make_event(
            EDREventType.PROCESS_START,
            pid=999,
            process="dropper.exe",
            target="C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe",
        ))

        # Same PID makes outbound connection
        alerts = engine.ingest(_make_event(
            EDREventType.NETWORK_CONNECT,
            pid=999,
            process="dropper.exe",
            target="185.220.101.1:4444",
            details={"remote_ip": "185.220.101.1", "remote_port": 4444},
        ))

        c2_alerts = [a for a in alerts if "C2" in a.rule_name]
        assert len(c2_alerts) == 1
        assert c2_alerts[0].severity == AlertSeverity.CRITICAL
        assert c2_alerts[0].mitre_technique == "T1071"

    def test_defense_evasion_rule(self):
        """Process disabling security tools triggers defense evasion alert."""
        engine = CorrelationEngine()

        alerts = engine.ingest(_make_event(
            EDREventType.PROCESS_START,
            pid=1234,
            process="cmd.exe",
            details={"cmdline": "net stop WinDefend"},
        ))

        evasion_alerts = [a for a in alerts if "Defense Evasion" in a.rule_name]
        assert len(evasion_alerts) == 1
        assert evasion_alerts[0].mitre_technique == "T1562"

    def test_credential_access_rule(self):
        """Known credential tool triggers alert."""
        engine = CorrelationEngine()

        alerts = engine.ingest(_make_event(
            EDREventType.PROCESS_START,
            pid=777,
            process="mimikatz.exe",
            target="C:\\tools\\mimikatz.exe",
        ))

        cred_alerts = [a for a in alerts if "Credential" in a.rule_name]
        assert len(cred_alerts) == 1
        assert cred_alerts[0].severity == AlertSeverity.CRITICAL

    def test_lateral_movement_rule(self):
        """PsExec execution triggers lateral movement alert."""
        engine = CorrelationEngine()

        alerts = engine.ingest(_make_event(
            EDREventType.PROCESS_START,
            pid=555,
            process="psexec.exe",
            target="C:\\tools\\psexec.exe",
        ))

        # Need NETWORK_CONNECT too for required_event_types
        alerts = engine.ingest(_make_event(
            EDREventType.NETWORK_CONNECT,
            pid=555,
            details={"remote_ip": "10.0.0.5", "remote_port": 445},
        ))

        lateral = [a for a in alerts if "Lateral" in a.rule_name]
        assert len(lateral) == 1


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Stats & Management
# ---------------------------------------------------------------------------

class TestEngineManagement:
    """Tests for engine stats and rule management."""

    def test_stats(self):
        engine = CorrelationEngine(rules=[])
        engine.ingest(_make_event(EDREventType.PROCESS_START))
        engine.ingest(_make_event(EDREventType.PROCESS_START))
        stats = engine.get_stats()
        assert stats["events_ingested"] == 2
        assert stats["active_rules"] == 0

    def test_add_rule_at_runtime(self):
        engine = CorrelationEngine(rules=[])
        assert len(engine.get_rules()) == 0

        engine.add_rule(CorrelationRule(
            name="Dynamic",
            description="Added at runtime",
            required_event_types={EDREventType.PROCESS_START},
        ))
        assert len(engine.get_rules()) == 1

    def test_callback_invoked(self):
        """on_alert callback fires when an alert is produced."""
        received: list[CorrelatedAlert] = []

        rule = CorrelationRule(
            name="Callback Test",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=1,
            window_seconds=60,
            group_by="global",
            condition=lambda events: (True, {}),
        )
        engine = CorrelationEngine(rules=[rule], on_alert=received.append)
        engine.ingest(_make_event(EDREventType.PROCESS_START))
        assert len(received) == 1
        assert received[0].rule_name == "Callback Test"


# ---------------------------------------------------------------------------
# TestCorrelationEngine — Thread Safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    """Verify the engine handles concurrent ingestion correctly."""

    def test_concurrent_ingestion(self):
        """Multiple threads ingesting events should not crash or corrupt state."""
        rule = CorrelationRule(
            name="Concurrency Test",
            description="test",
            required_event_types={EDREventType.PROCESS_START},
            min_events=5,
            window_seconds=60,
            group_by="global",
        )
        alerts: list[CorrelatedAlert] = []
        lock = threading.Lock()

        def safe_callback(alert):
            with lock:
                alerts.append(alert)

        engine = CorrelationEngine(rules=[rule], on_alert=safe_callback)

        def worker(thread_id: int):
            for i in range(20):
                engine.ingest(_make_event(
                    EDREventType.PROCESS_START,
                    pid=thread_id * 1000 + i,
                ))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        stats = engine.get_stats()
        assert stats["events_ingested"] == 100  # 5 threads × 20 events
        # At least one alert should have fired
        assert len(alerts) >= 1


# ---------------------------------------------------------------------------
# TestBuiltinRulesComplete
# ---------------------------------------------------------------------------

class TestBuiltinRulesComplete:
    """Ensure all built-in rules have valid configuration."""

    def test_all_rules_have_required_fields(self):
        for rule in BUILTIN_RULES:
            assert rule.name, "Rule missing name"
            assert rule.description, "Rule missing description"
            assert rule.required_event_types, "Rule missing required_event_types"
            assert rule.window_seconds > 0, f"Rule {rule.name}: invalid window"
            assert rule.min_events >= 1, f"Rule {rule.name}: invalid min_events"
            assert rule.severity in AlertSeverity, f"Rule {rule.name}: invalid severity"

    def test_builtin_rule_count(self):
        """We should have at least 7 built-in rules."""
        assert len(BUILTIN_RULES) >= 7
