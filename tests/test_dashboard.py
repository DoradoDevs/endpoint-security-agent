"""Tests for dashboard — models, API, and data operations."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from dashboard.models import DashboardDB, DeviceRecord, ScanRecord
from dashboard.api import DashboardAPI


@pytest.fixture
def db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_fleet.db"
        yield DashboardDB(db_path)


@pytest.fixture
def api(db):
    """Create a DashboardAPI with test database."""
    return DashboardAPI(db)


class TestDashboardDB:

    def test_register_and_get_device(self, db):
        device = DeviceRecord(
            device_id="dev1",
            hostname="test-host",
            os_name="Windows",
            os_version="10.0",
            agent_version="2.0.0",
            status="active",
        )
        db.register_device(device)

        loaded = db.get_device("dev1")
        assert loaded is not None
        assert loaded.hostname == "test-host"
        assert loaded.os_name == "Windows"

    def test_list_devices(self, db):
        db.register_device(DeviceRecord(device_id="dev1", hostname="host1", status="active"))
        db.register_device(DeviceRecord(device_id="dev2", hostname="host2", status="active"))
        db.register_device(DeviceRecord(device_id="dev3", hostname="host3", status="inactive"))

        all_devices = db.list_devices()
        assert len(all_devices) == 3

        active = db.list_devices(status="active")
        assert len(active) == 2

    def test_remove_device(self, db):
        db.register_device(DeviceRecord(device_id="dev1", hostname="host1"))
        assert db.remove_device("dev1") is True
        assert db.get_device("dev1") is None
        assert db.remove_device("nonexistent") is False

    def test_store_and_get_scan_result(self, db):
        db.register_device(DeviceRecord(device_id="dev1", hostname="host1"))

        scan = ScanRecord(
            device_id="dev1",
            timestamp="2024-01-01T00:00:00Z",
            risk_score=45.0,
            risk_grade="C",
            findings_count=10,
            scanners_run=json.dumps(["ProcessScanner", "NetworkScanner"]),
            severity_breakdown=json.dumps({"critical": 2, "high": 3}),
        )
        scan_id = db.store_scan_result(scan)
        assert scan_id > 0

        scans = db.get_device_scans("dev1")
        assert len(scans) == 1
        assert scans[0].risk_score == 45.0

    def test_fleet_summary(self, db):
        db.register_device(DeviceRecord(
            device_id="dev1", hostname="h1", status="active",
            last_risk_score=30.0, last_risk_grade="A",
        ))
        db.register_device(DeviceRecord(
            device_id="dev2", hostname="h2", status="active",
            last_risk_score=60.0, last_risk_grade="C",
        ))

        summary = db.get_fleet_summary()
        assert summary["total_devices"] == 2
        assert summary["active_devices"] == 2
        assert summary["average_risk_score"] == 45.0

    def test_store_and_get_policy(self, db):
        db.store_policy("pol1", "Strict", "Lock it down", '{"profile": "strict"}')
        db.register_device(DeviceRecord(device_id="dev1", hostname="h1"))
        db.assign_policy("dev1", "pol1")

        policy = db.get_device_policy("dev1")
        assert policy is not None
        assert policy["name"] == "Strict"

    def test_device_record_to_dict(self):
        device = DeviceRecord(
            device_id="dev1",
            hostname="test-host",
            tags='["production", "web"]',
        )
        d = device.to_dict()
        assert d["hostname"] == "test-host"
        assert d["tags"] == ["production", "web"]

    def test_scan_record_to_dict(self):
        scan = ScanRecord(
            device_id="dev1",
            scanners_run='["A", "B"]',
            severity_breakdown='{"high": 2}',
        )
        d = scan.to_dict()
        assert d["scanners_run"] == ["A", "B"]
        assert d["severity_breakdown"]["high"] == 2


class TestDashboardAPI:

    def test_enroll_device(self, api):
        result, status = api.enroll_device({
            "device_id": "dev1",
            "hostname": "test-host",
            "os_name": "Windows",
            "agent_version": "2.0.0",
        })
        assert status == 200
        assert result["success"] is True
        assert result["device_id"] == "dev1"

    def test_enroll_no_device_id(self, api):
        result, status = api.enroll_device({})
        assert status == 400

    def test_list_devices(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        api.enroll_device({"device_id": "dev2", "hostname": "h2"})

        result, status = api.list_devices()
        assert status == 200
        assert result["count"] == 2

    def test_get_device(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        result, status = api.get_device("dev1")
        assert status == 200
        assert result["device"]["hostname"] == "h1"

    def test_get_device_not_found(self, api):
        result, status = api.get_device("nonexistent")
        assert status == 404

    def test_remove_device(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        result, status = api.remove_device("dev1")
        assert status == 200
        assert result["success"] is True

    def test_submit_telemetry(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})

        result, status = api.submit_telemetry({
            "device_id": "dev1",
            "risk_score": 35.0,
            "risk_grade": "B",
            "findings_count": 5,
            "scanners_run": ["ProcessScanner"],
            "findings_by_severity": {"high": 2, "medium": 3},
        })
        assert status == 200
        assert result["success"] is True

    def test_submit_telemetry_unknown_device(self, api):
        result, status = api.submit_telemetry({
            "device_id": "unknown",
            "risk_score": 0,
        })
        assert status == 403

    def test_fleet_summary(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        result, status = api.get_fleet_summary()
        assert status == 200
        assert result["summary"]["total_devices"] >= 1

    def test_create_and_assign_policy(self, api):
        # Create policy
        result, status = api.create_policy({
            "policy_id": "pol1",
            "name": "Strict",
            "profile": "strict",
            "scan_depth": "deep",
        })
        assert status == 201

        # Enroll device and assign policy
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        result, status = api.assign_policy({
            "device_id": "dev1",
            "policy_id": "pol1",
        })
        assert status == 200

        # Verify policy assignment
        result, status = api.get_device_policy("dev1")
        assert status == 200
        assert result["name"] == "Strict"

    def test_recent_scans(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        api.submit_telemetry({
            "device_id": "dev1",
            "risk_score": 50.0,
            "risk_grade": "C",
            "findings_count": 10,
        })

        result, status = api.get_recent_scans(limit=10)
        assert status == 200
        assert result["count"] >= 1

    def test_device_history(self, api):
        api.enroll_device({"device_id": "dev1", "hostname": "h1"})
        api.submit_telemetry({"device_id": "dev1", "risk_score": 30, "risk_grade": "A"})
        api.submit_telemetry({"device_id": "dev1", "risk_score": 50, "risk_grade": "C"})

        result, status = api.get_device_history("dev1")
        assert status == 200
        assert result["count"] == 2
