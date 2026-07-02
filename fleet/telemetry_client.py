"""
Sentinel Fleet — Telemetry Client

Opt-in scan result transmission to fleet server for centralized monitoring.
All telemetry is explicitly enabled by the user. No data is sent without consent.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger
from core.telemetry import ScanResult


@dataclass
class TelemetryPayload:
    """Structured telemetry data for fleet server."""

    device_id: str
    timestamp: str
    scan_summary: dict[str, Any]
    findings_count: int
    risk_score: float
    risk_grade: str
    scanners_run: list[str]
    errors: list[str]
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "scan_summary": self.scan_summary,
            "findings_count": self.findings_count,
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "scanners_run": self.scanners_run,
            "errors": self.errors,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
        }


@dataclass
class TelemetryResponse:
    """Response from fleet server after telemetry submission."""

    success: bool = False
    message: str = ""
    server_actions: list[dict[str, Any]] = field(default_factory=list)


class TelemetryClient:
    """Sends opt-in scan telemetry to a fleet server."""

    def __init__(
        self,
        server_url: str,
        device_id: str,
        api_key: str = "",
        enabled: bool = False,
    ):
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.api_key = api_key
        self.enabled = enabled
        self.log = get_logger()

    def build_payload(self, result: ScanResult) -> TelemetryPayload:
        """Build a telemetry payload from scan results.

        Only summary data is sent — no raw findings or evidence.
        """
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}

        for finding in result.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = finding.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        scan_summary = {
            "hostname": result.system_info.hostname,
            "os_name": result.system_info.os_name,
            "os_version": result.system_info.os_version,
            "agent_version": result.system_info.agent_version,
            "scan_duration": result.scan_duration_seconds,
        }

        return TelemetryPayload(
            device_id=self.device_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_summary=scan_summary,
            findings_count=len(result.findings),
            risk_score=result.risk_score,
            risk_grade=result.risk_grade,
            scanners_run=result.scanners_run,
            errors=result.errors,
            findings_by_severity=severity_counts,
            findings_by_category=category_counts,
        )

    def submit(self, result: ScanResult) -> TelemetryResponse:
        """Submit scan telemetry to the fleet server.

        Returns TelemetryResponse with status and any server-side actions.
        """
        if not self.enabled:
            return TelemetryResponse(
                success=False,
                message="Telemetry is not enabled. Set fleet.telemetry_opt_in=true to enable.",
            )

        if not self.server_url:
            return TelemetryResponse(
                success=False,
                message="No fleet server URL configured",
            )

        payload = self.build_payload(result)

        try:
            url = f"{self.server_url}/api/v1/telemetry/submit"
            data = json.dumps(payload.to_dict()).encode("utf-8")

            headers = {
                "Content-Type": "application/json",
                "X-Device-ID": self.device_id,
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            req = urllib.request.Request(url, data=data, headers=headers, method="POST")

            with urllib.request.urlopen(req, timeout=30) as resp:
                response_data = json.loads(resp.read().decode())

            self.log.info(f"Telemetry submitted for device {self.device_id}")

            return TelemetryResponse(
                success=True,
                message="Telemetry submitted successfully",
                server_actions=response_data.get("actions", []),
            )

        except urllib.error.URLError as e:
            self.log.warning(f"Telemetry submission failed: {e}")
            return TelemetryResponse(
                success=False,
                message=f"Connection failed: {e}",
            )
        except Exception as e:
            self.log.error(f"Telemetry error: {e}")
            return TelemetryResponse(
                success=False,
                message=f"Telemetry error: {e}",
            )
