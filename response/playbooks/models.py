"""
Sentinel Agent — Playbook Models

Defines playbook data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlaybookTrigger:
    categories: list[str] = field(default_factory=list)
    min_severity: str = "high"
    keywords: list[str] = field(default_factory=list)

    def matches(self, finding) -> bool:
        # Check severity
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }
        finding_sev = getattr(finding, "severity", None)
        if finding_sev:
            finding_level = severity_order.get(
                finding_sev.value
                if hasattr(finding_sev, "value")
                else str(finding_sev).lower(),
                0,
            )
            min_level = severity_order.get(self.min_severity, 0)
            if finding_level < min_level:
                return False

        # Check categories
        if self.categories:
            finding_cat = getattr(finding, "category", "") or ""
            if not any(cat.lower() in finding_cat.lower() for cat in self.categories):
                return False

        # Check keywords
        if self.keywords:
            finding_text = (
                f"{getattr(finding, 'title', '')} "
                f"{getattr(finding, 'description', '')}"
            ).lower()
            if not any(kw.lower() in finding_text for kw in self.keywords):
                return False

        return True


@dataclass
class PlaybookAction:
    action_type: str  # kill_process_tree, quarantine, block_ip, isolate, notify, remove_persistence
    target_template: str = ""  # e.g., "{evidence.pid}", "{evidence.filepath}"
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookDefinition:
    name: str
    description: str
    trigger: PlaybookTrigger
    actions: list[PlaybookAction] = field(default_factory=list)
    notifications: list[str] = field(default_factory=list)
    rollback_on_failure: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "trigger": {
                "categories": self.trigger.categories,
                "min_severity": self.trigger.min_severity,
                "keywords": self.trigger.keywords,
            },
            "actions": [
                {
                    "action_type": a.action_type,
                    "target_template": a.target_template,
                    "params": a.params,
                }
                for a in self.actions
            ],
            "notifications": self.notifications,
            "rollback_on_failure": self.rollback_on_failure,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PlaybookDefinition:
        trigger = PlaybookTrigger(**data.get("trigger", {}))
        actions = [PlaybookAction(**a) for a in data.get("actions", [])]
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            trigger=trigger,
            actions=actions,
            notifications=data.get("notifications", []),
            rollback_on_failure=data.get("rollback_on_failure", True),
        )
