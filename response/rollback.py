"""
Sentinel Agent — Response Rollback Manager

Enables undoing response actions (restore quarantined files, unblock IPs)
using the audit log as source of truth.
"""

from __future__ import annotations

from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from response.audit import ResponseAuditLog
from response.models import ResponseRecord, ResponseType, ResponseStatus


class RollbackManager:
    """Manages rollback of response actions."""

    def __init__(
        self,
        audit_log: ResponseAuditLog | None = None,
        config: AgentConfig | None = None,
    ):
        self.log = get_logger()
        self.audit = audit_log or ResponseAuditLog()
        self._config = config

    def list_rollback_candidates(self, limit: int = 20) -> list[ResponseRecord]:
        """Get recent executed actions that can be rolled back.

        Returns up to *limit* candidates sorted by timestamp descending
        (most recent first).  Already-rolled-back actions are excluded by
        the underlying audit query.
        """
        candidates = self.audit.get_rollback_candidates()
        # get_rollback_candidates already filters status=EXECUTED + rollback_available
        # Return the most recent entries up to the limit
        return candidates[-limit:]

    # ------------------------------------------------------------------
    # Core rollback
    # ------------------------------------------------------------------

    def rollback(self, action_id: str) -> tuple[bool, str]:
        """Rollback a specific response action by its action_id."""
        record = self.audit.get_record_by_id(action_id)
        if record is None:
            return False, f"Action ID '{action_id}' not found in audit log"

        if record.status == ResponseStatus.ROLLED_BACK:
            return False, "Action already rolled back"

        if record.status != ResponseStatus.EXECUTED:
            return False, f"Cannot rollback action with status '{record.status}'"

        # Normalise response_type to the enum
        rtype = record.response_type
        if isinstance(rtype, str):
            rtype = ResponseType(rtype)

        if rtype == ResponseType.QUARANTINE_FILE:
            success, msg = self._rollback_quarantine(record)
        elif rtype == ResponseType.BLOCK_CONNECTION:
            success, msg = self._rollback_network_block(record)
        elif rtype == ResponseType.KILL_PROCESS:
            success, msg = self._rollback_process_kill(record)
        else:
            return False, f"Rollback not supported for action type: {rtype}"

        if success:
            # Record the rollback in the audit log
            rollback_record = ResponseRecord(
                action_name=f"Rollback: {record.action_name}",
                response_type=record.response_type,
                status=ResponseStatus.ROLLED_BACK,
                finding_title=record.finding_title,
                finding_severity=record.finding_severity,
                target=record.target,
                message=msg,
                rollback_available=False,
                metadata={"original_action_id": action_id},
            )
            self.audit.record(rollback_record)

        return success, msg

    # ------------------------------------------------------------------
    # Rollback + allowlist
    # ------------------------------------------------------------------

    def rollback_and_allowlist(self, action_id: str) -> tuple[bool, str]:
        """Rollback action and add target to allowlist to prevent re-trigger."""
        success, msg = self.rollback(action_id)
        if not success:
            return success, msg

        record = self.audit.get_record_by_id(action_id)
        if record is None:
            return success, msg  # Rollback succeeded but can't find record

        try:
            from core.allowlist import AllowlistManager

            mgr = AllowlistManager()
            target = record.target
            reason = f"Rollback of {record.action_name}: {record.finding_title}"

            rtype = record.response_type
            if isinstance(rtype, str):
                rtype = ResponseType(rtype)

            if rtype == ResponseType.QUARANTINE_FILE:
                mgr.add_path(target, reason=reason, added_by="rollback")
                msg += f" + allowlisted path: {target}"
            elif rtype == ResponseType.BLOCK_CONNECTION:
                # Store IP as hash entry for record-keeping
                mgr.add_hash(target, reason=reason, added_by="rollback")
                msg += f" + allowlisted: {target}"
            elif rtype == ResponseType.KILL_PROCESS:
                mgr.add_process(target, reason=reason, added_by="rollback")
                msg += f" + allowlisted process: {target}"
        except ImportError:
            msg += " (allowlist module not available)"

        return True, msg

    # ------------------------------------------------------------------
    # Per-type rollback handlers
    # ------------------------------------------------------------------

    def _rollback_quarantine(self, record: ResponseRecord) -> tuple[bool, str]:
        """Restore a quarantined file."""
        q_id = record.metadata.get("quarantine_id", "")
        if not q_id:
            return False, "No quarantine ID found in action metadata"

        try:
            from response.actions.file_response import FileQuarantineManager

            mgr = FileQuarantineManager(config=self._config)
            return mgr.restore(q_id)
        except ImportError:
            return False, "Quarantine manager not available"

    def _rollback_network_block(self, record: ResponseRecord) -> tuple[bool, str]:
        """Unblock a previously blocked IP."""
        ip = record.target
        if not ip:
            return False, "No IP address found in action record"

        try:
            from response.actions.network_response import NetworkResponseHandler

            handler = NetworkResponseHandler(self._config or AgentConfig())
            return handler.unblock_ip(ip)
        except ImportError:
            return False, "Network response handler not available"
        except Exception as e:
            return False, f"Failed to unblock IP: {e}"

    def _rollback_process_kill(self, record: ResponseRecord) -> tuple[bool, str]:
        """Process kills cannot be truly reversed.  Warn the user."""
        return True, (
            f"Process '{record.target}' was terminated and cannot be "
            f"restarted automatically. "
            f"Use --undo {record.action_id} --allowlist to prevent future kills."
        )
