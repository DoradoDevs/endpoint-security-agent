"""Tests for Sentinel Agent — Playbook Engine and Models."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, Severity
from response.playbooks.models import (
    PlaybookAction,
    PlaybookDefinition,
    PlaybookTrigger,
)
from response.playbooks.engine import PlaybookEngine
from response.playbooks.builtin import BUILTIN_PLAYBOOKS


# ---------------------------------------------------------------------------
# Helpers — fake finding objects
# ---------------------------------------------------------------------------


class FakeFinding:
    """Lightweight finding stand-in for tests."""

    def __init__(
        self,
        title: str = "Test Finding",
        description: str = "",
        severity=None,
        category: str = "",
        evidence: dict | None = None,
    ):
        self.title = title
        self.description = description
        self.severity = severity or Severity.HIGH
        self.category = category
        self.evidence = evidence or {}


# ---------------------------------------------------------------------------
# TestPlaybookTrigger
# ---------------------------------------------------------------------------


class TestPlaybookTrigger:
    """Tests for PlaybookTrigger matching logic."""

    def test_trigger_matches_category(self):
        """Category match returns True."""
        trigger = PlaybookTrigger(
            categories=["Ransomware"],
            min_severity="high",
            keywords=[],
        )
        finding = FakeFinding(
            title="Ransomware Detected",
            category="Ransomware",
            severity=Severity.CRITICAL,
        )

        assert trigger.matches(finding) is True

    def test_trigger_matches_severity(self):
        """Severity filter — low severity does not match high threshold."""
        trigger = PlaybookTrigger(
            categories=[],
            min_severity="high",
            keywords=[],
        )
        finding_high = FakeFinding(severity=Severity.HIGH)
        finding_low = FakeFinding(severity=Severity.LOW)

        assert trigger.matches(finding_high) is True
        assert trigger.matches(finding_low) is False

    def test_trigger_matches_keywords(self):
        """Keyword match in title/description."""
        trigger = PlaybookTrigger(
            categories=[],
            min_severity="info",
            keywords=["ransom", "encrypt"],
        )
        finding_match = FakeFinding(
            title="Ransomware file encryption detected",
            severity=Severity.HIGH,
        )
        finding_no_match = FakeFinding(
            title="Port scan detected",
            severity=Severity.HIGH,
        )

        assert trigger.matches(finding_match) is True
        assert trigger.matches(finding_no_match) is False

    def test_trigger_no_match(self):
        """Non-matching finding returns False."""
        trigger = PlaybookTrigger(
            categories=["Ransomware"],
            min_severity="high",
            keywords=["ransom"],
        )
        finding = FakeFinding(
            title="Open port detected",
            description="SSH port open",
            category="Network Security",
            severity=Severity.MEDIUM,
        )

        assert trigger.matches(finding) is False


# ---------------------------------------------------------------------------
# TestPlaybookEngine
# ---------------------------------------------------------------------------


class TestPlaybookEngine:
    """Tests for PlaybookEngine execution logic."""

    def test_find_matching_playbook(self):
        """Finding with ransomware category matches RANSOMWARE_RESPONSE."""
        engine = PlaybookEngine(config=AgentConfig())

        finding = FakeFinding(
            title="Ransomware encryption in progress",
            category="Ransomware",
            severity=Severity.CRITICAL,
        )

        pb = engine.find_matching_playbook(finding)

        assert pb is not None
        assert pb.name == "ransomware_response"

    def test_no_matching_playbook(self):
        """Finding with unknown category returns None."""
        engine = PlaybookEngine(config=AgentConfig())

        finding = FakeFinding(
            title="Informational note",
            category="Inventory",
            severity=Severity.INFO,
        )

        pb = engine.find_matching_playbook(finding)

        assert pb is None

    def test_execute_playbook_notify_only(self):
        """Execute playbook with only a notify action succeeds."""
        engine = PlaybookEngine(config=AgentConfig())

        playbook = PlaybookDefinition(
            name="test_notify",
            description="Test notification only",
            trigger=PlaybookTrigger(),
            actions=[
                PlaybookAction(
                    action_type="notify",
                    params={"message": "Test alert"},
                ),
            ],
        )

        finding = FakeFinding(title="Test threat")

        result = engine.execute_playbook(playbook, finding)

        assert result["playbook"] == "test_notify"
        assert result["actions_attempted"] == 1
        assert result["actions_succeeded"] == 1
        assert result["actions_failed"] == 0
        assert result["rolled_back"] is False
        assert len(result["details"]) == 1
        assert result["details"][0]["success"] is True

    def test_resolve_target(self):
        """Template resolution with evidence dict."""
        engine = PlaybookEngine(config=AgentConfig())

        finding = FakeFinding(
            title="Malware found",
            evidence={"pid": "1234", "filepath": "/tmp/malware.bin"},
        )

        resolved_pid = engine._resolve_target("{evidence.pid}", finding)
        resolved_path = engine._resolve_target("{evidence.filepath}", finding)
        resolved_empty = engine._resolve_target("", finding)

        assert resolved_pid == "1234"
        assert resolved_path == "/tmp/malware.bin"
        assert resolved_empty == ""

    def test_rollback_on_failure(self):
        """Action fails, verify rollback flag is set."""
        engine = PlaybookEngine(config=AgentConfig())

        playbook = PlaybookDefinition(
            name="test_rollback",
            description="Test rollback on failure",
            trigger=PlaybookTrigger(),
            actions=[
                PlaybookAction(
                    action_type="notify",
                    params={"message": "Step 1"},
                ),
                PlaybookAction(
                    action_type="kill_process_tree",
                    target_template="{evidence.pid}",
                ),
            ],
            rollback_on_failure=True,
        )

        finding = FakeFinding(
            title="Test threat",
            evidence={"pid": "99999999"},  # Non-existent PID
        )

        result = engine.execute_playbook(playbook, finding)

        # The notify should succeed, but kill_process should fail
        assert result["actions_attempted"] >= 2
        assert result["actions_failed"] >= 1
        assert result["rolled_back"] is True

    def test_list_playbooks(self):
        """Returns all 5 built-in playbooks."""
        engine = PlaybookEngine(config=AgentConfig())

        playbooks = engine.list_playbooks()

        assert len(playbooks) == 5
        names = {pb["name"] for pb in playbooks}
        assert "ransomware_response" in names
        assert "cryptominer_response" in names
        assert "rat_response" in names
        assert "data_exfil_response" in names
        assert "lateral_movement_response" in names

        for pb in playbooks:
            assert "name" in pb
            assert "description" in pb
            assert "actions" in pb
            assert pb["actions"] > 0


# ---------------------------------------------------------------------------
# TestPlaybookDefinition
# ---------------------------------------------------------------------------


class TestPlaybookDefinition:
    """Tests for PlaybookDefinition serialization."""

    def test_definition_roundtrip(self):
        """to_dict / from_dict produces equivalent playbook."""
        original = PlaybookDefinition(
            name="test_pb",
            description="A test playbook",
            trigger=PlaybookTrigger(
                categories=["Malware"],
                min_severity="critical",
                keywords=["trojan"],
            ),
            actions=[
                PlaybookAction(
                    action_type="quarantine",
                    target_template="{evidence.filepath}",
                ),
                PlaybookAction(
                    action_type="notify",
                    params={"message": "Malware quarantined"},
                ),
            ],
            notifications=["desktop", "email"],
            rollback_on_failure=True,
        )

        data = original.to_dict()
        restored = PlaybookDefinition.from_dict(data)

        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.trigger.categories == original.trigger.categories
        assert restored.trigger.min_severity == original.trigger.min_severity
        assert restored.trigger.keywords == original.trigger.keywords
        assert len(restored.actions) == len(original.actions)
        assert restored.actions[0].action_type == "quarantine"
        assert restored.actions[0].target_template == "{evidence.filepath}"
        assert restored.actions[1].action_type == "notify"
        assert restored.actions[1].params == {"message": "Malware quarantined"}
        assert restored.notifications == ["desktop", "email"]
        assert restored.rollback_on_failure is True

    def test_builtin_playbooks_valid(self):
        """All 5 built-in playbooks have names, triggers, and actions."""
        assert len(BUILTIN_PLAYBOOKS) == 5

        for pb in BUILTIN_PLAYBOOKS:
            assert isinstance(pb, PlaybookDefinition)
            assert pb.name, f"Playbook missing name: {pb}"
            assert pb.description, f"Playbook missing description: {pb.name}"
            assert isinstance(pb.trigger, PlaybookTrigger)
            assert len(pb.actions) > 0, f"Playbook has no actions: {pb.name}"

            # Verify each action has a valid type
            for action in pb.actions:
                assert isinstance(action, PlaybookAction)
                assert action.action_type in {
                    "kill_process_tree",
                    "quarantine",
                    "block_ip",
                    "isolate",
                    "notify",
                    "remove_persistence",
                }, f"Unknown action type: {action.action_type}"
