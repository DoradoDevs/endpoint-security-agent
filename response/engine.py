"""
Sentinel Agent — Threat Response Engine

Takes scan findings and executes appropriate automated responses
based on the security profile's response policy.
"""

from __future__ import annotations

from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from core.telemetry import Finding, ScanResult
from response.actions.file_response import FileQuarantineManager
from response.actions.network_response import NetworkResponseHandler
from response.actions.process_response import ProcessResponseHandler
from response.audit import ResponseAuditLog
from response.models import ResponseRecord, ResponseType, ResponseStatus
from response.policy import ResponsePolicy


class ThreatResponseEngine:
    """Takes scan findings and executes appropriate automated responses."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()
        self.policy = ResponsePolicy(config)
        self.audit = ResponseAuditLog()
        self._dry_run = getattr(config.scan, "dry_run", False)

    def respond(self, result: ScanResult) -> dict[str, Any]:
        """Process all findings and execute appropriate responses."""
        executed: list[ResponseRecord] = []
        skipped: list[ResponseRecord] = []
        errors: list[ResponseRecord] = []

        # Only process findings at or above minimum severity
        min_sev = self.policy.min_severity_for_response()
        actionable = [
            f for f in result.findings
            if f.severity.weight >= min_sev.weight
        ]

        if not self.policy.is_response_allowed():
            # Alert-only mode: log all findings but take no action
            for finding in actionable:
                record = ResponseRecord(
                    action_name="Alert Only",
                    response_type=ResponseType.ALERT_ONLY,
                    status=ResponseStatus.SKIPPED,
                    finding_title=finding.title,
                    finding_severity=finding.severity.value,
                    target=self._extract_target(finding),
                    message=f"Response not allowed by policy ({self.policy.level.value})",
                )
                skipped.append(record)
                self.audit.record(record)

            return self._build_result(executed, skipped, errors)

        process_handler = ProcessResponseHandler()
        file_handler = FileQuarantineManager()
        network_handler = NetworkResponseHandler()

        for finding in actionable:
            # Try process response
            if process_handler.is_applicable(finding):
                record = self._try_process_response(process_handler, finding)
                self._categorize_record(record, executed, skipped, errors)

            # Try file quarantine
            if file_handler.is_applicable(finding):
                record = self._try_file_response(file_handler, finding)
                self._categorize_record(record, executed, skipped, errors)

            # Try network block
            if network_handler.is_applicable(finding):
                record = self._try_network_response(network_handler, finding)
                self._categorize_record(record, executed, skipped, errors)

        return self._build_result(executed, skipped, errors)

    def _try_process_response(
        self, handler: Any, finding: Finding
    ) -> ResponseRecord:
        """Attempt to kill a suspicious process."""
        can_act, reason = handler.can_respond(finding)
        target = self._extract_target(finding)

        if not can_act:
            return ResponseRecord(
                action_name="Kill Process",
                response_type=ResponseType.KILL_PROCESS,
                status=ResponseStatus.SKIPPED,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message=reason,
            )

        if self._dry_run:
            record = ResponseRecord(
                action_name="Kill Process",
                response_type=ResponseType.KILL_PROCESS,
                status=ResponseStatus.DRY_RUN,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message=f"[DRY RUN] Would kill process: {reason}",
            )
            self.audit.record(record)
            return record

        success, message = handler.execute(finding)
        status = ResponseStatus.EXECUTED if success else ResponseStatus.FAILED
        record = ResponseRecord(
            action_name="Kill Process",
            response_type=ResponseType.KILL_PROCESS,
            status=status,
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            target=target,
            message=message,
        )
        self.audit.record(record)
        return record

    def _try_file_response(
        self, handler: Any, finding: Finding
    ) -> ResponseRecord:
        """Attempt to quarantine a suspicious file."""
        filepath = handler.get_filepath_from_finding(finding)
        target = filepath or self._extract_target(finding)

        if not filepath:
            return ResponseRecord(
                action_name="Quarantine File",
                response_type=ResponseType.QUARANTINE_FILE,
                status=ResponseStatus.SKIPPED,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message="No file path in finding evidence",
            )

        if self._dry_run:
            record = ResponseRecord(
                action_name="Quarantine File",
                response_type=ResponseType.QUARANTINE_FILE,
                status=ResponseStatus.DRY_RUN,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message=f"[DRY RUN] Would quarantine: {filepath}",
                rollback_available=True,
            )
            self.audit.record(record)
            return record

        success, message = handler.quarantine(filepath, finding)
        status = ResponseStatus.EXECUTED if success else ResponseStatus.FAILED
        record = ResponseRecord(
            action_name="Quarantine File",
            response_type=ResponseType.QUARANTINE_FILE,
            status=status,
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            target=target,
            message=message,
            rollback_available=success,
        )
        self.audit.record(record)
        return record

    def _try_network_response(
        self, handler: Any, finding: Finding
    ) -> ResponseRecord:
        """Attempt to block a suspicious IP."""
        ip = handler.get_ip_from_finding(finding)
        target = ip or self._extract_target(finding)

        if not ip:
            return ResponseRecord(
                action_name="Block IP",
                response_type=ResponseType.BLOCK_CONNECTION,
                status=ResponseStatus.SKIPPED,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message="No IP address in finding evidence",
            )

        if self._dry_run:
            record = ResponseRecord(
                action_name="Block IP",
                response_type=ResponseType.BLOCK_CONNECTION,
                status=ResponseStatus.DRY_RUN,
                finding_title=finding.title,
                finding_severity=finding.severity.value,
                target=target,
                message=f"[DRY RUN] Would block IP: {ip}",
                rollback_available=True,
            )
            self.audit.record(record)
            return record

        success, message = handler.block_ip(ip, finding)
        status = ResponseStatus.EXECUTED if success else ResponseStatus.FAILED
        record = ResponseRecord(
            action_name="Block IP",
            response_type=ResponseType.BLOCK_CONNECTION,
            status=status,
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            target=target,
            message=message,
            rollback_available=success,
        )
        self.audit.record(record)
        return record

    @staticmethod
    def _extract_target(finding: Finding) -> str:
        """Extract the primary target identifier from a finding."""
        evidence = finding.evidence
        for key in ("pid", "remote_ip", "ip", "path", "filepath", "ioc_value"):
            val = evidence.get(key)
            if val:
                return str(val)
        return finding.title

    @staticmethod
    def _categorize_record(
        record: ResponseRecord,
        executed: list[ResponseRecord],
        skipped: list[ResponseRecord],
        errors: list[ResponseRecord],
    ) -> None:
        if record.status in (ResponseStatus.EXECUTED, ResponseStatus.DRY_RUN):
            executed.append(record)
        elif record.status == ResponseStatus.FAILED:
            errors.append(record)
        else:
            skipped.append(record)

    def _build_result(
        self,
        executed: list[ResponseRecord],
        skipped: list[ResponseRecord],
        errors: list[ResponseRecord],
    ) -> dict[str, Any]:
        return {
            "executed": [r.to_dict() for r in executed],
            "skipped": [r.to_dict() for r in skipped],
            "errors": [r.to_dict() for r in errors],
            "policy_level": self.policy.level.value,
            "total_actions": len(executed),
            "total_skipped": len(skipped),
            "total_errors": len(errors),
        }
