"""
Sentinel Agent — Hardening Engine

Applies safe, reversible security hardening based on scan findings.

SECURITY MODEL:
- All actions require explicit confirmation (unless --auto mode)
- All actions are logged with before/after state
- Dry-run mode shows what would happen without making changes
- Only well-understood, vendor-recommended hardening is applied
- No destructive operations

v2.0: Platform-specific actions are in separate modules:
  - remediation/windows_hardening.py
  - remediation/macos_hardening.py
  - remediation/linux_hardening.py
"""

from __future__ import annotations

import platform
from typing import Any

from core.config import AgentConfig, Severity
from core.logging import get_logger, log_action
from core.telemetry import ScanResult, Finding


class HardeningAction:
    """Represents a single hardening action."""

    def __init__(
        self,
        name: str,
        description: str,
        severity: str,
        check_fn,
        apply_fn,
        rollback_fn=None,
        platform: str = "all",
    ):
        self.name = name
        self.description = description
        self.severity = severity
        self.check_fn = check_fn
        self.apply_fn = apply_fn
        self.rollback_fn = rollback_fn
        self.platform = platform


class HardeningEngine:
    """Applies safe security hardening based on scan findings."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()
        self.actions = self._build_actions()

    def _build_actions(self) -> list[HardeningAction]:
        """Build platform-appropriate hardening actions, filtered by profile."""
        system = platform.system().lower()
        actions: list[HardeningAction] = []

        if system == "windows":
            from remediation.windows_hardening import get_windows_actions
            actions.extend(get_windows_actions(self.config))
        elif system == "darwin":
            from remediation.macos_hardening import get_macos_actions
            actions.extend(get_macos_actions(self.config))
        elif system == "linux":
            from remediation.linux_hardening import get_linux_actions
            actions.extend(get_linux_actions(self.config))

        # Filter to current platform
        actions = [a for a in actions if a.platform in (system, "all")]

        # Filter by profile's allowed actions (if specified)
        try:
            from core.profiles import SecurityProfile, get_profile
            profile_name = getattr(self.config, "profile", "standard")
            if profile_name and profile_name != "custom":
                profile_spec = get_profile(SecurityProfile(profile_name))
                if profile_spec.hardening_actions_enabled:
                    actions = [a for a in actions
                               if a.name in profile_spec.hardening_actions_enabled]
        except (ValueError, KeyError, ImportError):
            pass  # Fall back to all actions if profile lookup fails

        return actions

    def apply(self, result: ScanResult) -> dict[str, Any]:
        """Apply hardening based on scan findings."""
        applied: list[dict] = []
        skipped: list[dict] = []
        errors: list[dict] = []

        self.log.info("=" * 50)
        self.log.info("HARDENING ENGINE — Starting")
        self.log.info(f"Mode: {'DRY-RUN' if self.config.scan.dry_run else 'LIVE'}")
        self.log.info(f"Auto: {'YES' if self.config.scan.auto_mode else 'NO (confirmation required)'}")
        self.log.info(f"Actions available: {len(self.actions)}")
        self.log.info("=" * 50)

        for action in self.actions:
            # Check if this action is needed
            try:
                needed, reason = action.check_fn()
            except Exception as e:
                self.log.debug(f"Check failed for {action.name}: {e}")
                continue

            if not needed:
                skipped.append({"name": action.name, "reason": "Already compliant"})
                continue

            self.log.info(f"\nAction: {action.name}")
            self.log.info(f"  Reason: {reason}")
            self.log.info(f"  Description: {action.description}")

            if self.config.scan.dry_run:
                log_action(action.name, "system", "Would apply (dry-run)", dry_run=True)
                applied.append({"name": action.name, "status": "dry-run", "reason": reason})
                continue

            if not self.config.scan.auto_mode:
                # In non-auto mode, we log what would be done but don't apply
                # Actual confirmation happens in the CLI layer
                applied.append({
                    "name": action.name,
                    "status": "pending_confirmation",
                    "reason": reason,
                    "description": action.description,
                })
                continue

            # Apply the action
            try:
                success, msg = action.apply_fn()
                if success:
                    log_action(action.name, "system", f"Applied: {msg}")
                    applied.append({"name": action.name, "status": "applied", "message": msg})
                else:
                    log_action(action.name, "system", f"Failed: {msg}")
                    errors.append({"name": action.name, "error": msg})
            except Exception as e:
                log_action(action.name, "system", f"Error: {e}")
                errors.append({"name": action.name, "error": str(e)})

        report = {
            "applied": applied,
            "skipped": skipped,
            "errors": errors,
            "total_actions": len(self.actions),
            "mode": "dry-run" if self.config.scan.dry_run else "live",
        }

        self.log.info(f"\nHardening complete: {len(applied)} applied, {len(skipped)} skipped, {len(errors)} errors")
        return report
