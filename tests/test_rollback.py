"""Tests for response rollback system."""

import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from response.rollback import RollbackManager
from response.audit import ResponseAuditLog
from response.models import ResponseRecord, ResponseType, ResponseStatus


def _make_record(
    action_name: str = "Test action",
    response_type: ResponseType = ResponseType.QUARANTINE_FILE,
    status: ResponseStatus = ResponseStatus.EXECUTED,
    finding_title: str = "Test finding",
    finding_severity: str = "high",
    target: str = "/tmp/evil.exe",
    rollback_available: bool = True,
    metadata: dict | None = None,
    action_id: str = "abc12345",
) -> ResponseRecord:
    return ResponseRecord(
        action_name=action_name,
        response_type=response_type,
        status=status,
        finding_title=finding_title,
        finding_severity=finding_severity,
        target=target,
        rollback_available=rollback_available,
        metadata=metadata or {},
        action_id=action_id,
    )


def _write_jsonl(log_file: Path, records: list[ResponseRecord]) -> None:
    """Write ResponseRecord list as JSONL to the given file."""
    with open(log_file, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec.to_dict()) + "\n")


class TestRollbackManager:
    """Tests for RollbackManager."""

    # ------------------------------------------------------------------
    # list_rollback_candidates
    # ------------------------------------------------------------------

    def test_list_rollback_candidates(self):
        """Only EXECUTED + rollback_available records should be returned."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            records = [
                _make_record(
                    action_name="Quarantine A",
                    action_id="aaa11111",
                    rollback_available=True,
                    status=ResponseStatus.EXECUTED,
                ),
                _make_record(
                    action_name="Quarantine B",
                    action_id="bbb22222",
                    rollback_available=False,
                    status=ResponseStatus.EXECUTED,
                ),
                _make_record(
                    action_name="Quarantine C",
                    action_id="ccc33333",
                    rollback_available=True,
                    status=ResponseStatus.FAILED,
                ),
                _make_record(
                    action_name="Quarantine D",
                    action_id="ddd44444",
                    rollback_available=True,
                    status=ResponseStatus.EXECUTED,
                ),
            ]
            _write_jsonl(audit.log_file, records)

            mgr = RollbackManager(audit_log=audit)
            candidates = mgr.list_rollback_candidates()

            assert len(candidates) == 2
            ids = [c.action_id for c in candidates]
            assert "aaa11111" in ids
            assert "ddd44444" in ids
            # bbb22222 excluded (rollback_available=False)
            # ccc33333 excluded (status=FAILED)

    # ------------------------------------------------------------------
    # rollback — quarantine
    # ------------------------------------------------------------------

    @patch("response.actions.file_response.FileQuarantineManager")
    def test_rollback_quarantine(self, MockFQM):
        """Rollback of quarantine should call FileQuarantineManager.restore."""
        mock_instance = MockFQM.return_value
        mock_instance.restore.return_value = (True, "File restored to /tmp/evil.exe")

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="quar0001",
                response_type=ResponseType.QUARANTINE_FILE,
                metadata={"quarantine_id": "q-abc-123"},
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("quar0001")

            assert success is True
            assert "restored" in msg.lower() or "File restored" in msg
            mock_instance.restore.assert_called_once_with("q-abc-123")

    # ------------------------------------------------------------------
    # rollback — network block
    # ------------------------------------------------------------------

    @patch("response.actions.network_response.NetworkResponseHandler")
    def test_rollback_network_block(self, MockNRH):
        """Rollback of network block should call unblock_ip with the correct IP."""
        mock_instance = MockNRH.return_value
        mock_instance.unblock_ip.return_value = (True, "Removed block for 10.0.0.1")

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="netb0001",
                response_type=ResponseType.BLOCK_CONNECTION,
                target="10.0.0.1",
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("netb0001")

            assert success is True
            assert "10.0.0.1" in msg
            mock_instance.unblock_ip.assert_called_once_with("10.0.0.1")

    # ------------------------------------------------------------------
    # rollback — process kill
    # ------------------------------------------------------------------

    def test_rollback_process_kill(self):
        """Process kill rollback should succeed with warning message."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="kill0001",
                response_type=ResponseType.KILL_PROCESS,
                target="evil.exe",
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("kill0001")

            assert success is True
            assert "evil.exe" in msg
            assert "cannot be restarted" in msg.lower()

    # ------------------------------------------------------------------
    # rollback — not found
    # ------------------------------------------------------------------

    def test_rollback_not_found(self):
        """Rollback of non-existent action_id should return False."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)
            # Write empty log file
            _write_jsonl(audit.log_file, [])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("nonexist")

            assert success is False
            assert "not found" in msg.lower()

    # ------------------------------------------------------------------
    # rollback — already rolled back
    # ------------------------------------------------------------------

    def test_rollback_already_rolled_back(self):
        """Attempting to rollback an already-rolled-back action should fail."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="done0001",
                status=ResponseStatus.ROLLED_BACK,
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("done0001")

            assert success is False
            assert "already rolled back" in msg.lower()

    # ------------------------------------------------------------------
    # rollback — audit record appended
    # ------------------------------------------------------------------

    @patch("response.actions.file_response.FileQuarantineManager")
    def test_rollback_records_in_audit(self, MockFQM):
        """A successful rollback should append a ROLLED_BACK record to audit."""
        mock_instance = MockFQM.return_value
        mock_instance.restore.return_value = (True, "File restored")

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="audt0001",
                response_type=ResponseType.QUARANTINE_FILE,
                metadata={"quarantine_id": "q-xyz"},
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            mgr.rollback("audt0001")

            # Audit log should now have 2 entries
            history = audit.get_history()
            assert len(history) == 2

            rollback_entry = history[1]
            assert rollback_entry.status in (
                ResponseStatus.ROLLED_BACK,
                ResponseStatus.ROLLED_BACK.value,
            )
            assert rollback_entry.action_name.startswith("Rollback:")
            assert rollback_entry.metadata.get("original_action_id") == "audt0001"

    # ------------------------------------------------------------------
    # rollback_and_allowlist — quarantine
    # ------------------------------------------------------------------

    @patch("response.actions.file_response.FileQuarantineManager")
    @patch("core.allowlist.AllowlistManager")
    def test_rollback_and_allowlist_quarantine(self, MockALM, MockFQM):
        """Rollback + allowlist for quarantine should call add_path."""
        mock_fqm = MockFQM.return_value
        mock_fqm.restore.return_value = (True, "File restored")

        mock_alm = MockALM.return_value

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="alq00001",
                response_type=ResponseType.QUARANTINE_FILE,
                target="/opt/app/legit.bin",
                metadata={"quarantine_id": "q-999"},
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback_and_allowlist("alq00001")

            assert success is True
            assert "allowlisted path" in msg
            mock_alm.add_path.assert_called_once()
            call_args = mock_alm.add_path.call_args
            assert call_args[0][0] == "/opt/app/legit.bin"
            assert call_args[1]["added_by"] == "rollback"

    # ------------------------------------------------------------------
    # rollback_and_allowlist — process
    # ------------------------------------------------------------------

    @patch("core.allowlist.AllowlistManager")
    def test_rollback_and_allowlist_process(self, MockALM):
        """Rollback + allowlist for process kill should call add_process."""
        mock_alm = MockALM.return_value

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="alp00001",
                response_type=ResponseType.KILL_PROCESS,
                target="safe_daemon",
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback_and_allowlist("alp00001")

            assert success is True
            assert "allowlisted process" in msg
            mock_alm.add_process.assert_called_once()
            call_args = mock_alm.add_process.call_args
            assert call_args[0][0] == "safe_daemon"
            assert call_args[1]["added_by"] == "rollback"

    # ------------------------------------------------------------------
    # rollback — unsupported type
    # ------------------------------------------------------------------

    def test_rollback_unsupported_type(self):
        """ALERT_ONLY actions should not be rollback-able."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="alrt0001",
                response_type=ResponseType.ALERT_ONLY,
                status=ResponseStatus.EXECUTED,
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("alrt0001")

            assert success is False
            assert "not supported" in msg.lower()

    # ------------------------------------------------------------------
    # rollback — quarantine without quarantine_id in metadata
    # ------------------------------------------------------------------

    def test_rollback_quarantine_no_quarantine_id(self):
        """Quarantine rollback should fail when metadata lacks quarantine_id."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="noqid001",
                response_type=ResponseType.QUARANTINE_FILE,
                metadata={},  # No quarantine_id
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("noqid001")

            assert success is False
            assert "quarantine ID" in msg or "quarantine_id" in msg.lower()

    # ------------------------------------------------------------------
    # list_rollback_candidates respects limit
    # ------------------------------------------------------------------

    def test_list_rollback_candidates_limit(self):
        """list_rollback_candidates should respect the limit parameter."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            records = [
                _make_record(
                    action_id=f"lim{i:05d}",
                    status=ResponseStatus.EXECUTED,
                    rollback_available=True,
                )
                for i in range(10)
            ]
            _write_jsonl(audit.log_file, records)

            mgr = RollbackManager(audit_log=audit)
            candidates = mgr.list_rollback_candidates(limit=3)

            assert len(candidates) == 3

    # ------------------------------------------------------------------
    # rollback — status not EXECUTED (e.g. PENDING)
    # ------------------------------------------------------------------

    def test_rollback_wrong_status(self):
        """Cannot rollback an action that is still PENDING."""
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            audit = ResponseAuditLog(log_dir=log_dir)

            record = _make_record(
                action_id="pend0001",
                status=ResponseStatus.PENDING,
            )
            _write_jsonl(audit.log_file, [record])

            mgr = RollbackManager(audit_log=audit)
            success, msg = mgr.rollback("pend0001")

            assert success is False
            assert "status" in msg.lower()
