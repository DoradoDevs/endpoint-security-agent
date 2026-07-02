"""
Tests for mesh.peer_manager and mesh.threat_sharing -- peer registration,
health monitoring, stale-peer eviction, threat alert creation/sharing,
alert deduplication, finding-to-alert conversion, and severity thresholds.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

from core.config import Severity
from core.telemetry import Finding
from mesh.peer_manager import PeerInfo, PeerManager
from mesh.threat_sharing import ThreatAlert, ThreatSharingService


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_finding(
    severity: Severity = Severity.HIGH,
    title: str = "Open SSH port",
    category: str = "network",
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        title=title,
        description="Test finding description",
        severity=severity,
        category=category,
        scanner="test_scanner",
        evidence={"port": 22, "service": "ssh"},
    )


# ------------------------------------------------------------------
# Peer registration and lookup
# ------------------------------------------------------------------


class TestPeerRegistration:
    """Verify peer registration, update, and lookup behaviour."""

    def test_register_new_peer(self) -> None:
        pm = PeerManager()
        peer = pm.register_peer("agent-001", "192.168.1.10", 51338)
        assert peer.device_id == "agent-001"
        assert peer.ip_address == "192.168.1.10"
        assert peer.comm_port == 51338
        assert peer.status == "active"
        assert len(pm) == 1

    def test_register_updates_existing_peer(self) -> None:
        pm = PeerManager()
        pm.register_peer("agent-001", "192.168.1.10", 51338)
        peer = pm.register_peer("agent-001", "192.168.1.20", 51339)
        assert peer.ip_address == "192.168.1.20"
        assert peer.comm_port == 51339
        assert len(pm) == 1  # no duplicate entry

    def test_register_multiple_peers(self) -> None:
        pm = PeerManager()
        pm.register_peer("a", "10.0.0.1", 1000)
        pm.register_peer("b", "10.0.0.2", 1001)
        pm.register_peer("c", "10.0.0.3", 1002)
        assert len(pm) == 3

    def test_get_peer_exists(self) -> None:
        pm = PeerManager()
        pm.register_peer("agent-001", "10.0.0.1", 5000)
        peer = pm.get_peer("agent-001")
        assert peer is not None
        assert peer.device_id == "agent-001"

    def test_get_peer_missing_returns_none(self) -> None:
        pm = PeerManager()
        assert pm.get_peer("nonexistent") is None

    def test_contains_operator(self) -> None:
        pm = PeerManager()
        pm.register_peer("a", "10.0.0.1", 1000)
        assert "a" in pm
        assert "b" not in pm

    def test_get_active_peers(self) -> None:
        pm = PeerManager()
        pm.register_peer("a", "10.0.0.1", 1000)
        pm.register_peer("b", "10.0.0.2", 1001)
        active = pm.get_active_peers()
        assert len(active) == 2
        ids = {p.device_id for p in active}
        assert ids == {"a", "b"}

    def test_remove_peer(self) -> None:
        pm = PeerManager()
        pm.register_peer("agent-001", "10.0.0.1", 5000)
        pm.remove_peer("agent-001")
        assert len(pm) == 0
        assert pm.get_peer("agent-001") is None

    def test_remove_nonexistent_peer_does_not_raise(self) -> None:
        pm = PeerManager()
        pm.remove_peer("ghost")  # must not raise

    def test_peer_info_to_dict(self) -> None:
        peer = PeerInfo(device_id="a-001", ip_address="10.0.0.5", comm_port=9999)
        d = peer.to_dict()
        assert d["device_id"] == "a-001"
        assert d["ip_address"] == "10.0.0.5"
        assert d["comm_port"] == 9999
        assert d["status"] == "active"

    def test_peer_info_default_timestamps_are_iso(self) -> None:
        peer = PeerInfo(device_id="x", ip_address="1.2.3.4", comm_port=1)
        datetime.fromisoformat(peer.first_seen)
        datetime.fromisoformat(peer.last_seen)


# ------------------------------------------------------------------
# Peer health monitoring / heartbeat
# ------------------------------------------------------------------


class TestPeerHeartbeat:
    """Verify heartbeat updates and status refreshing."""

    def test_heartbeat_updates_last_seen(self) -> None:
        pm = PeerManager()
        pm.register_peer("agent-001", "192.168.1.10", 51338)
        old_ts = pm.get_peer("agent-001").last_seen
        time.sleep(0.01)
        pm.update_heartbeat("agent-001")
        new_ts = pm.get_peer("agent-001").last_seen
        assert new_ts >= old_ts

    def test_heartbeat_sets_status_active(self) -> None:
        pm = PeerManager()
        pm.register_peer("agent-001", "10.0.0.1", 5000)
        # Simulate a stale status by directly modifying the field
        pm.peers["agent-001"].status = "stale"
        pm.update_heartbeat("agent-001")
        assert pm.get_peer("agent-001").status == "active"

    def test_heartbeat_unknown_peer_ignored(self) -> None:
        pm = PeerManager()
        pm.update_heartbeat("nonexistent")  # must not raise
        assert len(pm) == 0


# ------------------------------------------------------------------
# Peer timeout eviction
# ------------------------------------------------------------------


class TestPeerEviction:
    """Verify automatic eviction of stale peers."""

    def test_evict_stale_removes_old_peer(self) -> None:
        pm = PeerManager(timeout_seconds=1)
        pm.register_peer("agent-001", "10.0.0.1", 5000)
        stale_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        pm.peers["agent-001"].last_seen = stale_time

        evicted = pm.evict_stale()
        assert "agent-001" in evicted
        assert len(pm) == 0

    def test_evict_stale_keeps_fresh_peer(self) -> None:
        pm = PeerManager(timeout_seconds=300)
        pm.register_peer("agent-001", "10.0.0.1", 5000)
        evicted = pm.evict_stale()
        assert evicted == []
        assert len(pm) == 1

    def test_evict_mixed_stale_and_fresh(self) -> None:
        pm = PeerManager(timeout_seconds=5)
        pm.register_peer("fresh", "10.0.0.1", 5000)
        pm.register_peer("stale", "10.0.0.2", 5001)
        stale_time = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        pm.peers["stale"].last_seen = stale_time

        evicted = pm.evict_stale()
        assert "stale" in evicted
        assert "fresh" not in evicted
        assert len(pm) == 1

    def test_evict_unparseable_timestamp(self) -> None:
        pm = PeerManager(timeout_seconds=60)
        pm.register_peer("bad-ts", "10.0.0.1", 5000)
        pm.peers["bad-ts"].last_seen = "not-a-timestamp"
        evicted = pm.evict_stale()
        assert "bad-ts" in evicted


# ------------------------------------------------------------------
# Threat alert creation and sharing
# ------------------------------------------------------------------


class TestThreatAlertCreation:
    """Verify ThreatAlert construction and serialization."""

    def test_create_alert_from_finding(self) -> None:
        finding = _make_finding()
        alert = ThreatAlert.from_finding(finding, "agent-001")
        assert alert.finding_title == "Open SSH port"
        assert alert.finding_severity == "high"
        assert alert.finding_category == "network"
        assert alert.source_device == "agent-001"

    def test_alert_evidence_summary(self) -> None:
        finding = _make_finding()
        alert = ThreatAlert.from_finding(finding, "agent-001")
        assert alert.evidence_summary == {"port": 22, "service": "ssh"}

    def test_alert_to_dict_keys(self) -> None:
        alert = ThreatAlert.from_finding(_make_finding(), "agent-001")
        d = alert.to_dict()
        expected_keys = {
            "alert_id",
            "finding_title",
            "finding_severity",
            "finding_category",
            "source_device",
            "timestamp",
            "evidence_summary",
        }
        assert set(d.keys()) == expected_keys

    def test_alert_from_dict_round_trip(self) -> None:
        original = ThreatAlert.from_finding(_make_finding(), "agent-001")
        d = original.to_dict()
        restored = ThreatAlert.from_dict(d)
        assert restored.finding_title == original.finding_title
        assert restored.finding_severity == original.finding_severity
        assert restored.source_device == original.source_device
        assert restored.alert_id == original.alert_id

    def test_service_create_alert(self) -> None:
        svc = ThreatSharingService()
        finding = _make_finding(Severity.CRITICAL)
        alert = svc.create_alert(finding, "agent-001")
        assert isinstance(alert, ThreatAlert)
        assert alert.finding_severity == "critical"


# ------------------------------------------------------------------
# Alert deduplication
# ------------------------------------------------------------------


class TestAlertDeduplication:
    """Verify that duplicate alerts are rejected."""

    def test_receive_new_alert(self) -> None:
        svc = ThreatSharingService()
        alert = ThreatAlert(
            finding_title="Test",
            finding_severity="high",
            finding_category="test",
            source_device="agent-002",
            alert_id="unique-001",
        )
        assert svc.receive_alert(alert) is True
        assert len(svc.get_received_alerts()) == 1

    def test_receive_duplicate_alert_rejected(self) -> None:
        svc = ThreatSharingService()
        alert = ThreatAlert(
            finding_title="Test",
            finding_severity="high",
            finding_category="test",
            source_device="agent-002",
            alert_id="dup-001",
        )
        assert svc.receive_alert(alert) is True
        assert svc.receive_alert(alert) is False
        assert len(svc.get_received_alerts()) == 1

    def test_different_alert_ids_both_accepted(self) -> None:
        svc = ThreatSharingService()
        a1 = ThreatAlert(
            finding_title="Alert A",
            finding_severity="high",
            finding_category="test",
            source_device="agent-002",
            alert_id="id-aaa",
        )
        a2 = ThreatAlert(
            finding_title="Alert B",
            finding_severity="critical",
            finding_category="test",
            source_device="agent-003",
            alert_id="id-bbb",
        )
        assert svc.receive_alert(a1) is True
        assert svc.receive_alert(a2) is True
        assert len(svc.get_received_alerts()) == 2

    def test_get_received_alerts_returns_copy(self) -> None:
        svc = ThreatSharingService()
        alert = ThreatAlert(
            finding_title="Test",
            finding_severity="high",
            finding_category="test",
            source_device="agent-002",
            alert_id="copy-test",
        )
        svc.receive_alert(alert)
        alerts = svc.get_received_alerts()
        alerts.clear()
        assert len(svc.get_received_alerts()) == 1


# ------------------------------------------------------------------
# Alert severity thresholds
# ------------------------------------------------------------------


class TestAlertSeverityThresholds:
    """Verify severity-based filtering via should_share."""

    def test_critical_above_high_threshold(self) -> None:
        svc = ThreatSharingService(min_severity="high")
        assert svc.should_share(_make_finding(Severity.CRITICAL)) is True

    def test_high_meets_high_threshold(self) -> None:
        svc = ThreatSharingService(min_severity="high")
        assert svc.should_share(_make_finding(Severity.HIGH)) is True

    def test_medium_below_high_threshold(self) -> None:
        svc = ThreatSharingService(min_severity="high")
        assert svc.should_share(_make_finding(Severity.MEDIUM)) is False

    def test_low_below_high_threshold(self) -> None:
        svc = ThreatSharingService(min_severity="high")
        assert svc.should_share(_make_finding(Severity.LOW)) is False

    def test_info_below_high_threshold(self) -> None:
        svc = ThreatSharingService(min_severity="high")
        assert svc.should_share(_make_finding(Severity.INFO)) is False

    def test_medium_threshold_accepts_medium(self) -> None:
        svc = ThreatSharingService(min_severity="medium")
        assert svc.should_share(_make_finding(Severity.MEDIUM)) is True

    def test_medium_threshold_rejects_low(self) -> None:
        svc = ThreatSharingService(min_severity="medium")
        assert svc.should_share(_make_finding(Severity.LOW)) is False

    def test_info_threshold_accepts_all(self) -> None:
        svc = ThreatSharingService(min_severity="info")
        for sev in Severity:
            assert svc.should_share(_make_finding(sev)) is True

    def test_critical_threshold_only_critical(self) -> None:
        svc = ThreatSharingService(min_severity="critical")
        assert svc.should_share(_make_finding(Severity.CRITICAL)) is True
        assert svc.should_share(_make_finding(Severity.HIGH)) is False
