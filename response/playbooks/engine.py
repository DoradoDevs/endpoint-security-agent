"""
Sentinel Agent — Playbook Engine

Executes response playbooks when findings match triggers.
"""

from __future__ import annotations

import re
from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from response.playbooks.models import PlaybookAction, PlaybookDefinition


class PlaybookEngine:
    """Executes automated response playbooks."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.log = get_logger()
        self._playbooks: list[PlaybookDefinition] = []
        self._load_playbooks()

    def _load_playbooks(self) -> None:
        """Load built-in and custom playbooks."""
        try:
            from response.playbooks.builtin import BUILTIN_PLAYBOOKS

            self._playbooks.extend(BUILTIN_PLAYBOOKS)
        except ImportError:
            pass

    def find_matching_playbook(self, finding) -> PlaybookDefinition | None:
        """Find the first playbook matching a finding."""
        for pb in self._playbooks:
            if pb.trigger.matches(finding):
                return pb
        return None

    def execute_playbook(
        self, playbook: PlaybookDefinition, finding
    ) -> dict[str, Any]:
        """Execute a playbook against a finding. Returns result dict."""
        self.log.info(
            f"[Playbook] Executing '{playbook.name}' for: "
            f"{getattr(finding, 'title', 'unknown')}"
        )

        result = {
            "playbook": playbook.name,
            "finding": getattr(finding, "title", ""),
            "actions_attempted": 0,
            "actions_succeeded": 0,
            "actions_failed": 0,
            "details": [],
            "rolled_back": False,
        }

        executed_actions = []

        for action in playbook.actions:
            result["actions_attempted"] += 1
            target = self._resolve_target(action.target_template, finding)

            try:
                success, message = self._execute_action(action, target, finding)
                action_result = {
                    "action_type": action.action_type,
                    "target": target,
                    "success": success,
                    "message": message,
                }
                result["details"].append(action_result)

                if success:
                    result["actions_succeeded"] += 1
                    executed_actions.append((action, target))
                else:
                    result["actions_failed"] += 1
                    if playbook.rollback_on_failure:
                        self.log.warning(
                            f"[Playbook] Action failed, rolling back: {message}"
                        )
                        self._rollback_actions(executed_actions)
                        result["rolled_back"] = True
                        break
            except Exception as e:
                result["actions_failed"] += 1
                result["details"].append(
                    {
                        "action_type": action.action_type,
                        "target": target,
                        "success": False,
                        "message": str(e),
                    }
                )
                if playbook.rollback_on_failure:
                    self._rollback_actions(executed_actions)
                    result["rolled_back"] = True
                    break

        # Send notifications
        for notification in playbook.notifications:
            self._send_notification(notification, playbook, finding, result)

        return result

    def _resolve_target(self, template: str, finding) -> str:
        """Resolve a target template like {evidence.pid} to actual value."""
        if not template:
            return ""

        evidence = getattr(finding, "evidence", {}) or {}

        # Replace {evidence.KEY} patterns
        def replacer(match):
            key = match.group(1)
            parts = key.split(".")
            if parts[0] == "evidence" and len(parts) > 1:
                return str(evidence.get(parts[1], ""))
            elif parts[0] == "finding":
                return (
                    str(getattr(finding, parts[1], "")) if len(parts) > 1 else ""
                )
            return match.group(0)

        return re.sub(r"\{([^}]+)\}", replacer, template)

    def _execute_action(
        self, action: PlaybookAction, target: str, finding
    ) -> tuple[bool, str]:
        """Execute a single playbook action."""
        if action.action_type == "kill_process_tree":
            return self._action_kill_process(target)
        elif action.action_type == "quarantine":
            return self._action_quarantine(target, finding)
        elif action.action_type == "block_ip":
            return self._action_block_ip(target)
        elif action.action_type == "isolate":
            return self._action_isolate()
        elif action.action_type == "notify":
            return self._action_notify(
                action.params.get("message", "Threat detected")
            )
        elif action.action_type == "remove_persistence":
            return True, f"Persistence removal requested for {target}"
        else:
            return False, f"Unknown action type: {action.action_type}"

    def _action_kill_process(self, target: str) -> tuple[bool, str]:
        try:
            import psutil

            pid = int(target) if target.isdigit() else 0
            if pid:
                proc = psutil.Process(pid)
                proc.kill()
                return True, f"Process {pid} killed"
            return False, "Invalid PID"
        except ImportError:
            return False, "psutil not available"
        except Exception as e:
            return False, str(e)

    def _action_quarantine(self, target: str, finding) -> tuple[bool, str]:
        try:
            from response.actions.file_response import FileQuarantineManager

            mgr = FileQuarantineManager()
            return mgr.quarantine(
                target,
                finding_title=getattr(finding, "title", "Playbook action"),
                finding_severity=getattr(finding, "severity", "high"),
            )
        except ImportError:
            return False, "Quarantine module not available"

    def _action_block_ip(self, target: str) -> tuple[bool, str]:
        try:
            from response.actions.network_response import NetworkResponseHandler

            handler = NetworkResponseHandler()
            return handler.block_ip(target)
        except ImportError:
            return False, "Network response not available"

    def _action_isolate(self) -> tuple[bool, str]:
        try:
            from response.actions.endpoint_isolation import (
                EndpointIsolationManager,
            )

            mgr = EndpointIsolationManager()
            return mgr.isolate(timeout_hours=2)
        except ImportError:
            return False, "Isolation module not available"

    def _action_notify(self, message: str) -> tuple[bool, str]:
        try:
            from core.notifications import NotificationManager

            nm = NotificationManager()
            nm.notify("Sentinel Playbook Alert", message, "high")
            return True, "Notification sent"
        except (ImportError, Exception):
            return True, f"Notification: {message}"

    def _rollback_actions(self, executed_actions: list) -> None:
        """Attempt to rollback executed actions."""
        for action, target in reversed(executed_actions):
            try:
                if action.action_type == "quarantine":
                    from response.actions.file_response import (
                        FileQuarantineManager,
                    )

                    mgr = FileQuarantineManager()
                    # Try to find and restore
                    entries = mgr.list_quarantined()
                    for entry in entries:
                        if entry.original_path == target:
                            mgr.restore(entry.quarantine_id)
                            break
                elif action.action_type == "block_ip":
                    from response.actions.network_response import (
                        NetworkResponseHandler,
                    )

                    handler = NetworkResponseHandler()
                    handler.unblock_ip(target)
            except Exception as e:
                self.log.error(
                    f"[Playbook] Rollback failed for {action.action_type}: {e}"
                )

    def _send_notification(
        self, notification, playbook, finding, result
    ) -> None:
        try:
            from core.notifications import NotificationManager

            nm = NotificationManager()
            nm.notify(
                f"Sentinel Playbook: {playbook.name}",
                f"Executed for {getattr(finding, 'title', 'threat')}. "
                f"Actions: {result['actions_succeeded']}/{result['actions_attempted']} succeeded.",
                "high",
            )
        except (ImportError, Exception):
            pass

    def list_playbooks(self) -> list[dict]:
        """List all available playbooks."""
        return [
            {
                "name": pb.name,
                "description": pb.description,
                "actions": len(pb.actions),
            }
            for pb in self._playbooks
        ]
