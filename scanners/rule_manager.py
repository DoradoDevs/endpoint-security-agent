"""
Sentinel Agent — Malware Rule Manager

Manages custom malware detection rules: downloading from remote sources,
merging with built-in rules, and persisting to disk.  Custom rules are
stored as JSON and can override built-in rules by name.

SECURITY: Downloaded rule sets are validated before being applied.
Always verify the source URL is trusted before calling update_rules().
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests

from core.config import Severity
from scanners.malware_rules import BUILTIN_RULES, MalwareRule


# ------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------

@dataclass
class RuleSetInfo:
    """Metadata about the currently loaded rule set."""

    version: str
    rule_count: int
    last_updated: str  # ISO-8601 timestamp
    source_url: str


# ------------------------------------------------------------------
# Rule manager
# ------------------------------------------------------------------

class RuleManager:
    """Download, validate, persist and merge malware detection rules."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or self._default_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = self.data_dir / "custom_rules.json"
        self.meta_file = self.data_dir / "rules_meta.json"

    # -- platform default directory ------------------------------------

    @staticmethod
    def _default_data_dir() -> Path:
        """Return the platform-specific data directory for rule storage."""
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "rules"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "rules"
        else:
            return Path.home() / ".sentinel" / "rules"

    # -- update from remote --------------------------------------------

    def update_rules(self, url: str) -> tuple[bool, str]:
        """Download a rule set from *url*, validate and persist it.

        Returns ``(True, message)`` on success or ``(False, error)`` on
        failure.  If the remote version matches the currently stored
        version the update is skipped.
        """
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            return False, f"Network error: {exc}"

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return False, "Invalid JSON in response"

        valid, err = self._validate_rules(data)
        if not valid:
            return False, err

        # Skip if version already matches
        current_meta = self._read_meta()
        if current_meta and current_meta.get("version") == data["version"]:
            return False, f"Already at version {data['version']}"

        # Persist rules and metadata
        self.rules_file.write_text(json.dumps(data, indent=2))
        meta = {
            "version": data["version"],
            "rule_count": len(data["rules"]),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "source_url": url,
        }
        self.meta_file.write_text(json.dumps(meta, indent=2))

        count = len(data["rules"])
        return True, f"Updated to version {data['version']} \u2014 {count} rules"

    # -- load / merge --------------------------------------------------

    def load_custom_rules(self) -> list[MalwareRule]:
        """Load custom rules from the local JSON file.

        Returns an empty list when no custom rules have been downloaded.
        """
        if not self.rules_file.exists():
            return []

        try:
            data = json.loads(self.rules_file.read_text())
            return [self._dict_to_rule(r) for r in data.get("rules", [])]
        except (json.JSONDecodeError, KeyError, ValueError):
            return []

    def get_merged_rules(self) -> list[MalwareRule]:
        """Return built-in rules merged with custom rules.

        Custom rules override built-in rules that share the same name.
        Additional custom rules are appended at the end.
        """
        custom = self.load_custom_rules()
        if not custom:
            return list(BUILTIN_RULES)

        custom_by_name: dict[str, MalwareRule] = {r.name: r for r in custom}

        merged: list[MalwareRule] = []
        for builtin in BUILTIN_RULES:
            if builtin.name in custom_by_name:
                merged.append(custom_by_name.pop(builtin.name))
            else:
                merged.append(builtin)

        # Append any remaining custom rules that are purely new
        merged.extend(custom_by_name.values())
        return merged

    # -- info ----------------------------------------------------------

    def get_info(self) -> RuleSetInfo:
        """Return metadata about the current rule set (builtin + custom)."""
        meta = self._read_meta()
        merged = self.get_merged_rules()

        if meta:
            return RuleSetInfo(
                version=meta.get("version", "unknown"),
                rule_count=len(merged),
                last_updated=meta.get("last_updated", ""),
                source_url=meta.get("source_url", ""),
            )

        return RuleSetInfo(
            version="builtin",
            rule_count=len(BUILTIN_RULES),
            last_updated="",
            source_url="",
        )

    # -- serialisation helpers -----------------------------------------

    def _dict_to_rule(self, data: dict) -> MalwareRule:
        """Convert a JSON dictionary to a :class:`MalwareRule`.

        Handles ``byte_patterns`` stored as hex strings and ``severity``
        stored as a lowercase string.
        """
        byte_patterns: list[bytes] = []
        for hexstr in data.get("byte_patterns", []):
            byte_patterns.append(bytes.fromhex(hexstr))

        return MalwareRule(
            name=data["name"],
            description=data["description"],
            severity=Severity(data["severity"].lower()),
            category=data["category"],
            byte_patterns=byte_patterns,
            string_patterns=data.get("string_patterns", []),
            regex_patterns=data.get("regex_patterns", []),
            file_extensions=data.get("file_extensions", []),
            max_file_size=data.get("max_file_size", 50 * 1024 * 1024),
            min_matches=data.get("min_matches", 1),
        )

    def _rule_to_dict(self, rule: MalwareRule) -> dict:
        """Convert a :class:`MalwareRule` to a JSON-serialisable dict.

        Byte patterns are stored as hex strings and the severity enum is
        stored as its lowercase string value.
        """
        return {
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.value,
            "category": rule.category,
            "byte_patterns": [bp.hex() for bp in rule.byte_patterns],
            "string_patterns": list(rule.string_patterns),
            "regex_patterns": list(rule.regex_patterns),
            "file_extensions": list(rule.file_extensions),
            "max_file_size": rule.max_file_size,
            "min_matches": rule.min_matches,
        }

    # -- validation ----------------------------------------------------

    def _validate_rules(self, data: dict) -> tuple[bool, str]:
        """Validate the top-level structure and each rule in *data*.

        Returns ``(True, "")`` when valid, or ``(False, description)``
        on the first validation error encountered.
        """
        if "version" not in data:
            return False, "Missing 'version' key"

        if "rules" not in data or not isinstance(data["rules"], list):
            return False, "Missing or invalid 'rules' list"

        required_fields = {"name", "description", "severity", "category"}
        valid_severities = {s.value for s in Severity}

        for idx, rule in enumerate(data["rules"]):
            for field in required_fields:
                if field not in rule:
                    return False, f"Rule {idx}: missing required field '{field}'"

            if rule["severity"].lower() not in valid_severities:
                return False, f"Rule {idx}: invalid severity '{rule['severity']}'"

        return True, ""

    # -- private helpers -----------------------------------------------

    def _read_meta(self) -> dict | None:
        """Read the metadata file, returning *None* if absent or invalid."""
        if not self.meta_file.exists():
            return None
        try:
            return json.loads(self.meta_file.read_text())
        except (json.JSONDecodeError, ValueError):
            return None
