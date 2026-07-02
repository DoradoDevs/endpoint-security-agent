"""
Sentinel Dashboard — REST API

REST endpoints for device management, policy push, and result aggregation.
Designed to work with or without Flask — provides both a Flask blueprint
and a standalone HTTP handler.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from dashboard.models import DashboardDB, DeviceRecord, ScanRecord

log = get_logger()


class DashboardAPI:
    """Core API logic for the fleet dashboard, framework-agnostic."""

    def __init__(self, db: DashboardDB | None = None):
        self.db = db or DashboardDB()

    # === Device Endpoints ===

    def enroll_device(self, data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """POST /api/v1/devices/enroll"""
        device_id = data.get("device_id", "")
        if not device_id:
            return {"error": "device_id is required"}, 400

        now = datetime.now(timezone.utc).isoformat()
        device = DeviceRecord(
            device_id=device_id,
            hostname=data.get("hostname", ""),
            os_name=data.get("os_name", ""),
            os_version=data.get("os_version", ""),
            agent_version=data.get("agent_version", ""),
            enrolled_at=now,
            status="active",
        )

        self.db.register_device(device)
        log.info(f"Device enrolled: {device_id} ({device.hostname})")

        # Return any assigned policy
        policy = self.db.get_device_policy(device_id)

        return {
            "success": True,
            "device_id": device_id,
            "message": "Device enrolled successfully",
            "policies": policy or {},
        }, 200

    def list_devices(self, status: str = "") -> tuple[dict[str, Any], int]:
        """GET /api/v1/devices"""
        devices = self.db.list_devices(status=status)
        return {
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
        }, 200

    def get_device(self, device_id: str) -> tuple[dict[str, Any], int]:
        """GET /api/v1/devices/<device_id>"""
        device = self.db.get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} not found"}, 404
        return {"device": device.to_dict()}, 200

    def remove_device(self, device_id: str) -> tuple[dict[str, Any], int]:
        """DELETE /api/v1/devices/<device_id>"""
        removed = self.db.remove_device(device_id)
        if not removed:
            return {"error": f"Device {device_id} not found"}, 404
        log.info(f"Device removed: {device_id}")
        return {"success": True, "message": f"Device {device_id} removed"}, 200

    # === Telemetry Endpoints ===

    def submit_telemetry(self, data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """POST /api/v1/telemetry/submit"""
        device_id = data.get("device_id", "")
        if not device_id:
            return {"error": "device_id is required"}, 400

        # Verify device is enrolled
        device = self.db.get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} is not enrolled"}, 403

        scan = ScanRecord(
            device_id=device_id,
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            risk_score=data.get("risk_score", 0.0),
            risk_grade=data.get("risk_grade", ""),
            findings_count=data.get("findings_count", 0),
            scanners_run=json.dumps(data.get("scanners_run", [])),
            errors=json.dumps(data.get("errors", [])),
            severity_breakdown=json.dumps(data.get("findings_by_severity", {})),
            category_breakdown=json.dumps(data.get("findings_by_category", {})),
        )

        scan_id = self.db.store_scan_result(scan)
        log.info(f"Telemetry stored for {device_id}: score={scan.risk_score}")

        return {
            "success": True,
            "scan_id": scan_id,
            "message": "Telemetry received",
            "actions": [],
        }, 200

    # === Fleet Summary ===

    def get_fleet_summary(self) -> tuple[dict[str, Any], int]:
        """GET /api/v1/fleet/summary"""
        summary = self.db.get_fleet_summary()
        return {"summary": summary}, 200

    def get_device_history(
        self, device_id: str, limit: int = 50
    ) -> tuple[dict[str, Any], int]:
        """GET /api/v1/devices/<device_id>/history"""
        device = self.db.get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} not found"}, 404

        scans = self.db.get_device_scans(device_id, limit=limit)
        return {
            "device_id": device_id,
            "scans": [s.to_dict() for s in scans],
            "count": len(scans),
        }, 200

    def get_recent_scans(self, limit: int = 100) -> tuple[dict[str, Any], int]:
        """GET /api/v1/scans/recent"""
        scans = self.db.get_recent_scans(limit=limit)
        return {
            "scans": [s.to_dict() for s in scans],
            "count": len(scans),
        }, 200

    # === Policy Endpoints ===

    def get_device_policy(self, device_id: str) -> tuple[dict[str, Any], int]:
        """GET /api/v1/devices/<device_id>/policy"""
        device = self.db.get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} not found"}, 404

        policy = self.db.get_device_policy(device_id)
        if not policy:
            return {
                "device_id": device_id,
                "policy": None,
                "message": "No policy assigned",
            }, 200

        return {
            "device_id": device_id,
            "policy_id": policy["policy_id"],
            "name": policy["name"],
            "description": policy["description"],
            "profile": json.loads(policy.get("config_json", "{}")).get("profile", "standard"),
            "scan_depth": json.loads(policy.get("config_json", "{}")).get("scan_depth", "standard"),
            "min_severity": json.loads(policy.get("config_json", "{}")).get("min_severity", "info"),
            "enabled_scanners": json.loads(policy.get("config_json", "{}")).get("enabled_scanners", []),
            "hardening_enabled": json.loads(policy.get("config_json", "{}")).get("hardening_enabled", False),
            "auto_remediate": json.loads(policy.get("config_json", "{}")).get("auto_remediate", False),
            "scan_interval_minutes": json.loads(policy.get("config_json", "{}")).get("scan_interval_minutes", 60),
            "force_compliance": json.loads(policy.get("config_json", "{}")).get("force_compliance", False),
        }, 200

    def create_policy(self, data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """POST /api/v1/policies"""
        policy_id = data.get("policy_id", "")
        name = data.get("name", "")
        if not policy_id or not name:
            return {"error": "policy_id and name are required"}, 400

        config = {
            "profile": data.get("profile", "standard"),
            "scan_depth": data.get("scan_depth", "standard"),
            "min_severity": data.get("min_severity", "info"),
            "enabled_scanners": data.get("enabled_scanners", []),
            "hardening_enabled": data.get("hardening_enabled", False),
            "auto_remediate": data.get("auto_remediate", False),
            "scan_interval_minutes": data.get("scan_interval_minutes", 60),
            "force_compliance": data.get("force_compliance", False),
        }

        self.db.store_policy(
            policy_id=policy_id,
            name=name,
            description=data.get("description", ""),
            config_json=json.dumps(config),
        )

        log.info(f"Policy created: {name} ({policy_id})")
        return {"success": True, "policy_id": policy_id}, 201

    def assign_policy(self, data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """POST /api/v1/policies/assign"""
        device_id = data.get("device_id", "")
        policy_id = data.get("policy_id", "")

        if not device_id or not policy_id:
            return {"error": "device_id and policy_id are required"}, 400

        device = self.db.get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} not found"}, 404

        self.db.assign_policy(device_id, policy_id)
        log.info(f"Policy {policy_id} assigned to device {device_id}")

        return {
            "success": True,
            "message": f"Policy {policy_id} assigned to device {device_id}",
        }, 200
