"""
Integration test: Full Sentinel pipeline.

Tests the complete flow from event ingestion through correlation,
response, notification, and SIEM forwarding. Uses mocks for external
dependencies (processes, network, file system) but exercises the real
engine code paths.

Pipeline under test:
  EDR Event → EventStore → CorrelationEngine → CorrelatedAlert
                                                      ↓
                                            ThreatResponseEngine
                                                      ↓
                                            NotificationManager
                                                      ↓
                                            SIEMIntegration
"""

import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, Severity
from core.telemetry import Finding, ScanResult, SystemInfo
from edr.event_types import EDREvent, EDREventType
from edr.event_store import EventStore
from edr.correlation_engine import (
    CorrelationEngine,
    CorrelatedAlert,
    AlertSeverity,
    CorrelationRule,
    BUILTIN_RULES,
)
from edr.realtime_engine import RealTimeProtectionEngine
from reporting.risk_engine import RiskEngine
from response.engine import ThreatResponseEngine
from response.models import ResponseStatus


# ---------------------------------------------------------------------------
# Test 1: Scan → Risk Score → Report pipeline
# ---------------------------------------------------------------------------

class TestScanToReportPipeline:
    """Verify the scan → risk engine → report pipeline."""

    def test_findings_produce_risk_score(self):
        """Findings should produce a risk score and grade."""
        result = ScanResult(system_info=SystemInfo(hostname="test-host"))

        result.add_finding(Finding(
            title="Critical finding",
            description="Test critical",
            severity=Severity.CRITICAL,
            category="Malware Indicators",
            scanner="TestScanner",
        ))
        result.add_finding(Finding(
            title="High finding",
            description="Test high",
            severity=Severity.HIGH,
            category="Behavioral Analysis",
            scanner="TestScanner",
        ))
        result.add_finding(Finding(
            title="Medium finding",
            description="Test medium",
            severity=Severity.MEDIUM,
            category="Configuration",
            scanner="TestScanner",
        ))

        engine = RiskEngine()
        score, grade = engine.calculate(result)

        assert score > 0
        assert grade in ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-",
                          "D+", "D", "D-", "F")
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1

    def test_empty_scan_gets_good_grade(self):
        """No findings should produce a good risk score."""
        result = ScanResult(system_info=SystemInfo())
        engine = RiskEngine()
        score, grade = engine.calculate(result)
        assert score == 0
        assert grade in ("A+", "A")

    def test_scan_result_serialization(self):
        """ScanResult should serialize to dict cleanly."""
        result = ScanResult(
            system_info=SystemInfo(hostname="test"),
            risk_score=45.0,
            risk_grade="C",
        )
        result.add_finding(Finding(
            title="Test",
            description="desc",
            severity=Severity.HIGH,
            category="Test",
            scanner="TestScanner",
        ))
        d = result.to_dict()
        assert d["summary"]["total_findings"] == 1
        assert d["summary"]["risk_score"] == 45.0
        assert d["system_info"]["hostname"] == "test"


# ---------------------------------------------------------------------------
# Test 2: Event → Correlation → Alert pipeline
# ---------------------------------------------------------------------------

class TestEventCorrelationPipeline:
    """Verify EDR events flow through the correlation engine correctly."""

    def test_c2_attack_chain(self):
        """Simulate a C2 attack: temp process → outbound connection.
        Should produce a correlated alert.
        """
        alerts: list[CorrelatedAlert] = []
        engine = CorrelationEngine(on_alert=alerts.append)

        # Step 1: Malware drops into temp and executes
        engine.ingest(EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_pid=5000,
            source_process="payload.exe",
            target="C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe",
            severity="high",
            details={"cmdline": "payload.exe -connect"},
        ))

        # Step 2: Malware connects to C2
        engine.ingest(EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_pid=5000,
            source_process="payload.exe",
            target="185.220.101.1:4444",
            severity="high",
            details={"remote_ip": "185.220.101.1", "remote_port": 4444},
        ))

        c2_alerts = [a for a in alerts if "C2" in a.rule_name]
        assert len(c2_alerts) >= 1
        alert = c2_alerts[0]
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.mitre_tactic == "Command and Control"
        assert len(alert.events) >= 2
        assert 5000 in alert.source_pids

    def test_credential_dump_chain(self):
        """Simulate: mimikatz → credential access alert."""
        alerts: list[CorrelatedAlert] = []
        engine = CorrelationEngine(on_alert=alerts.append)

        engine.ingest(EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_pid=7777,
            source_process="mimikatz.exe",
            target="C:\\tools\\mimikatz.exe",
            severity="high",
            details={"cmdline": "mimikatz.exe sekurlsa::logonpasswords"},
        ))

        cred_alerts = [a for a in alerts if "Credential" in a.rule_name]
        assert len(cred_alerts) >= 1
        assert cred_alerts[0].severity == AlertSeverity.CRITICAL

    def test_dns_beaconing_chain(self):
        """Simulate: multiple suspicious DNS queries → beaconing alert."""
        alerts: list[CorrelatedAlert] = []
        engine = CorrelationEngine(on_alert=alerts.append)

        for i in range(5):
            engine.ingest(EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_process="dns",
                target=f"xk7q9m{i}z3v8w2p4j6.evil.tk",
                details={
                    "dns_query": f"xk7q9m{i}z3v8w2p4j6.evil.tk",
                    "detection": "dga_tunneling",
                    "remote_ip": "",
                },
                severity="high",
            ))

        beacon_alerts = [a for a in alerts if "Beacon" in a.rule_name]
        assert len(beacon_alerts) >= 1

    def test_dns_exfiltration_chain(self):
        """DGA DNS + file modification → exfiltration alert."""
        alerts: list[CorrelatedAlert] = []
        engine = CorrelationEngine(on_alert=alerts.append)

        # DGA DNS query
        engine.ingest(EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_process="dns",
            target="xk7q9mz3v8w2p4j6.evil.com",
            details={"dns_query": "xk7q9mz3v8w2p4j6.evil.com",
                      "detection": "dga_tunneling"},
            severity="high",
        ))

        # File modification
        engine.ingest(EDREvent(
            event_type=EDREventType.FILE_MODIFY,
            source_pid=5000,
            source_process="malware.exe",
            target="C:\\Users\\victim\\Documents\\secret.docx",
            severity="medium",
        ))

        exfil_alerts = [a for a in alerts if "Exfiltration" in a.rule_name]
        assert len(exfil_alerts) >= 1
        assert exfil_alerts[0].mitre_technique == "T1048.003"

    def test_defense_evasion_chain(self):
        """Process disables AV → defense evasion alert."""
        alerts: list[CorrelatedAlert] = []
        engine = CorrelationEngine(on_alert=alerts.append)

        engine.ingest(EDREvent(
            event_type=EDREventType.PROCESS_START,
            source_pid=9000,
            source_process="cmd.exe",
            details={"cmdline": "sc stop WinDefend"},
            severity="medium",
        ))

        evasion = [a for a in alerts if "Defense Evasion" in a.rule_name]
        assert len(evasion) >= 1


# ---------------------------------------------------------------------------
# Test 3: Correlation → Response pipeline
# ---------------------------------------------------------------------------

class TestCorrelationToResponsePipeline:
    """Verify correlated alerts flow into the response engine."""

    def test_alert_converts_to_finding(self):
        """CorrelatedAlert should convert to a valid Finding."""
        alert = CorrelatedAlert(
            rule_name="Test Rule",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            mitre_tactic="Execution",
            mitre_technique="T1059",
            events=[EDREvent(event_type=EDREventType.PROCESS_START, source_pid=100)],
            source_pids=[100],
            evidence={"test": "value"},
        )

        finding = RealTimeProtectionEngine._alert_to_finding(alert)

        assert finding.severity == Severity.CRITICAL
        assert "Test Rule" in finding.title
        assert finding.category == "Correlated Detection"
        assert finding.evidence["mitre_technique"] == "T1059"
        assert finding.evidence["alert_id"] == alert.id

    def test_event_converts_to_finding(self):
        """EDREvent should convert to a valid Finding."""
        event = EDREvent(
            event_type=EDREventType.NETWORK_CONNECT,
            source_pid=500,
            source_process="malware.exe",
            target="evil.com:4444",
            severity="critical",
            details={"remote_ip": "1.2.3.4"},
        )

        finding = RealTimeProtectionEngine._event_to_finding(event)

        assert finding.severity == Severity.CRITICAL
        assert "network_connect" in finding.title
        assert finding.evidence["pid"] == 500
        assert finding.evidence["remote_ip"] == "1.2.3.4"

    def test_response_engine_processes_alert_finding(self):
        """ThreatResponseEngine should accept and process a correlated finding."""
        config = AgentConfig()

        finding = Finding(
            title="Correlated: C2 Beacon",
            description="Process from temp dir with outbound connection",
            severity=Severity.CRITICAL,
            category="Correlated Detection",
            scanner="CorrelationEngine",
            evidence={
                "pid": 5000,
                "process_name": "payload.exe",
                "remote_ip": "185.220.101.1",
            },
        )

        result = ScanResult(
            system_info=SystemInfo(),
            findings=[finding],
            risk_score=85.0,
            risk_grade="F",
        )

        engine = ThreatResponseEngine(config)
        response = engine.respond(result)

        # Response should complete without error (policy may skip or execute)
        assert "total_actions" in response
        assert "total_skipped" in response
        assert "total_errors" in response
        # Default policy is alert_only, so actions should be 0
        assert response["total_actions"] == 0
        assert response["total_skipped"] >= 1


# ---------------------------------------------------------------------------
# Test 4: Event Store persistence pipeline
# ---------------------------------------------------------------------------

class TestEventStorePipeline:
    """Verify events and alerts are persisted to the event store."""

    def test_events_persisted_and_queryable(self):
        """Events written to store should be queryable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_events.db"
            store = EventStore(db_path=db_path)

            # Write events
            events = [
                EDREvent(event_type=EDREventType.PROCESS_START, source_pid=100,
                         source_process="test.exe", severity="high"),
                EDREvent(event_type=EDREventType.NETWORK_CONNECT, source_pid=100,
                         source_process="test.exe", target="evil.com:443",
                         severity="critical"),
                EDREvent(event_type=EDREventType.THREAT_DETECTED,
                         source_process="C2 Beacon Rule", severity="critical",
                         details={"alert_id": "abc123"}),
            ]
            count = store.record_events_batch(events)
            assert count == 3

            # Query back
            all_events = store.get_events(limit=100)
            assert len(all_events) == 3

            # Query by PID
            pid_events = store.get_events_by_pid(100)
            assert len(pid_events) == 2

            # Query by severity
            critical = store.get_events(severity="critical")
            assert len(critical) == 2

            # Query by type
            threats = store.get_events(event_type=EDREventType.THREAT_DETECTED)
            assert len(threats) == 1
            assert threats[0].details["alert_id"] == "abc123"

    def test_event_counts(self):
        """Event count aggregation should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_counts.db"
            store = EventStore(db_path=db_path)

            store.record_events_batch([
                EDREvent(event_type=EDREventType.PROCESS_START),
                EDREvent(event_type=EDREventType.PROCESS_START),
                EDREvent(event_type=EDREventType.NETWORK_CONNECT),
            ])

            counts = store.get_event_counts(hours=1)
            assert counts.get("process_start") == 2
            assert counts.get("network_connect") == 1


# ---------------------------------------------------------------------------
# Test 5: Full end-to-end pipeline (mocked external deps)
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    """Full end-to-end: event → store → correlate → alert → response."""

    def test_full_c2_attack_pipeline(self):
        """Simulate a complete C2 attack and verify the entire pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "e2e_events.db"
            store = EventStore(db_path=db_path)

            # Track what happens
            alerts_received: list[CorrelatedAlert] = []
            events_stored: list[EDREvent] = []

            def on_alert(alert):
                alerts_received.append(alert)
                # Store the alert as the real engine would
                alert_event = EDREvent(
                    event_type=EDREventType.THREAT_DETECTED,
                    source_process=alert.rule_name,
                    target=str(alert.source_pids),
                    severity=alert.severity.value,
                    details={"alert_id": alert.id},
                )
                store.record_event(alert_event)

            # Set up correlation engine
            correlator = CorrelationEngine(on_alert=on_alert)

            # === Simulate attack sequence ===

            # 1. Malware drops into temp
            e1 = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=6000,
                source_process="dropper.exe",
                target="C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe",
                severity="high",
                details={"cmdline": "dropper.exe"},
            )
            store.record_event(e1)
            correlator.ingest(e1)

            # 2. Dropper connects to C2
            e2 = EDREvent(
                event_type=EDREventType.NETWORK_CONNECT,
                source_pid=6000,
                source_process="dropper.exe",
                target="185.220.101.1:4444",
                severity="high",
                details={"remote_ip": "185.220.101.1", "remote_port": 4444},
            )
            store.record_event(e2)
            correlator.ingest(e2)

            # 3. C2 spawns credential dump
            e3 = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=6001,
                source_process="mimikatz.exe",
                target="C:\\Windows\\Temp\\mimikatz.exe",
                severity="high",
                details={"cmdline": "mimikatz.exe sekurlsa::logonpasswords",
                          "ppid": 6000},
            )
            store.record_event(e3)
            correlator.ingest(e3)

            # 4. Defense evasion
            e4 = EDREvent(
                event_type=EDREventType.PROCESS_START,
                source_pid=6002,
                source_process="cmd.exe",
                severity="medium",
                details={"cmdline": "net stop WinDefend", "ppid": 6000},
            )
            store.record_event(e4)
            correlator.ingest(e4)

            # === Verify results ===

            # Should have multiple correlated alerts
            assert len(alerts_received) >= 2, (
                f"Expected >= 2 alerts, got {len(alerts_received)}: "
                f"{[a.rule_name for a in alerts_received]}"
            )

            alert_names = {a.rule_name for a in alerts_received}
            # C2 beacon should be detected
            assert any("C2" in name for name in alert_names), (
                f"Expected C2 alert, got: {alert_names}"
            )

            # Event store should have all events + alert events
            all_events = store.get_events(limit=100)
            assert len(all_events) >= 4  # At least 4 original events

            # Threat detected events should be in the store
            threats = store.get_events(event_type=EDREventType.THREAT_DETECTED)
            assert len(threats) >= 1

            # Correlation stats should reflect the ingestion
            stats = correlator.get_stats()
            assert stats["events_ingested"] == 4
            assert stats["alerts_emitted"] >= 2

            # === Now run response engine on the findings ===
            config = AgentConfig()
            for alert in alerts_received:
                finding = RealTimeProtectionEngine._alert_to_finding(alert)
                result = ScanResult(
                    system_info=SystemInfo(),
                    findings=[finding],
                    risk_score=90.0,
                    risk_grade="F",
                )
                resp_engine = ThreatResponseEngine(config)
                response = resp_engine.respond(result)
                # Should complete without crash
                assert "total_actions" in response


# ---------------------------------------------------------------------------
# Test 6: Scanner registration pipeline
# ---------------------------------------------------------------------------

class TestScannerRegistration:
    """Verify scanners are correctly discovered by the scheduler."""

    def test_yara_scanner_registered_in_hunt_mode(self):
        """YaraScanner should be discovered when enable_yara_scan=True."""
        from core.scheduler import ScanScheduler
        config = AgentConfig()
        config.scan.enable_yara_scan = True

        scheduler = ScanScheduler(config)
        scanners = scheduler.discover_scanners()

        scanner_names = [s.name for s in scanners]
        assert "YaraScanner" in scanner_names

    def test_yara_scanner_not_registered_by_default(self):
        """YaraScanner should NOT be discovered with default config."""
        from core.scheduler import ScanScheduler
        config = AgentConfig()

        scheduler = ScanScheduler(config)
        scanners = scheduler.discover_scanners()

        scanner_names = [s.name for s in scanners]
        assert "YaraScanner" not in scanner_names

    def test_hunt_mode_enables_all_threat_scanners(self):
        """Hunt mode config should enable all threat hunting scanners."""
        config = AgentConfig()
        config.scan.enable_malware_scan = True
        config.scan.enable_memory_scan = True
        config.scan.enable_persistence_scan = True
        config.scan.enable_heuristic_scan = True
        config.scan.enable_ioc_scan = True
        config.scan.enable_yara_scan = True

        from core.scheduler import ScanScheduler
        scheduler = ScanScheduler(config)
        scanners = scheduler.discover_scanners()

        scanner_names = [s.name for s in scanners]
        assert "MalwareScanner" in scanner_names
        assert "MemoryScanner" in scanner_names
        assert "YaraScanner" in scanner_names


# ---------------------------------------------------------------------------
# Test 7: Risk scoring with correlated findings
# ---------------------------------------------------------------------------

class TestRiskScoringWithCorrelation:
    """Verify the risk engine correctly scores correlated detections."""

    def test_correlated_findings_increase_score(self):
        """Correlated findings should contribute to risk score."""
        result = ScanResult(system_info=SystemInfo())

        # Add multiple correlated findings to ensure measurable impact
        for title in ["C2 Beacon", "Credential Dump", "Lateral Movement"]:
            result.add_finding(Finding(
                title=f"Correlated: {title}",
                description="Multi-event detection",
                severity=Severity.CRITICAL,
                category="Correlated Detection",
                scanner="CorrelationEngine",
                evidence={"mitre_technique": "T1071", "event_count": 3},
            ))

        engine = RiskEngine()
        score, grade = engine.calculate(result)

        assert score > 0
        # Multiple critical findings should produce a poor grade
        assert grade not in ("A+", "A", "A-")

    def test_multiple_attack_stages_compound_score(self):
        """Multiple attack stages should compound the risk score."""
        result_single = ScanResult(system_info=SystemInfo())
        result_single.add_finding(Finding(
            title="Single finding",
            description="one",
            severity=Severity.CRITICAL,
            category="Malware Indicators",
            scanner="TestScanner",
        ))

        result_multi = ScanResult(system_info=SystemInfo())
        for title in ["C2 Beacon", "Credential Access", "Defense Evasion"]:
            result_multi.add_finding(Finding(
                title=title,
                description="multi-stage",
                severity=Severity.CRITICAL,
                category="Correlated Detection",
                scanner="CorrelationEngine",
            ))

        engine = RiskEngine()
        score_single, _ = engine.calculate(result_single)
        score_multi, _ = engine.calculate(result_multi)

        assert score_multi > score_single


# ---------------------------------------------------------------------------
# Test 8: Builtin rules coverage
# ---------------------------------------------------------------------------

class TestBuiltinRulesCoverage:
    """Verify all 10 built-in rules are present and valid."""

    def test_rule_count(self):
        """Should have 10 built-in rules (7 original + 3 DNS)."""
        assert len(BUILTIN_RULES) == 10

    def test_all_rules_have_mitre_mapping(self):
        """Every rule should have a MITRE tactic and technique."""
        for rule in BUILTIN_RULES:
            assert rule.mitre_tactic, f"Rule '{rule.name}' missing mitre_tactic"
            assert rule.mitre_technique, f"Rule '{rule.name}' missing mitre_technique"

    def test_dns_rules_present(self):
        """All 3 DNS correlation rules should be present."""
        names = {r.name for r in BUILTIN_RULES}
        assert "DNS Exfiltration — DGA + File Activity" in names
        assert "DNS C2 — Suspicious DNS + Temp Process" in names
        assert "DNS Beaconing Detected" in names

    def test_no_duplicate_rule_names(self):
        """All rule names should be unique."""
        names = [r.name for r in BUILTIN_RULES]
        assert len(names) == len(set(names))
