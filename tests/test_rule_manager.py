"""Tests for the malware Rule Manager."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import requests

from core.config import Severity
from scanners.malware_rules import BUILTIN_RULES, MalwareRule
from scanners.rule_manager import RuleManager, RuleSetInfo


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _sample_rule_dict(
    name: str = "test_rule",
    severity: str = "high",
    **overrides,
) -> dict:
    """Return a minimal valid rule dictionary."""
    base = {
        "name": name,
        "description": "A test rule for unit testing",
        "severity": severity,
        "category": "Test",
        "string_patterns": ["test_pattern"],
        "regex_patterns": [],
        "file_extensions": [],
        "max_file_size": 52428800,
        "min_matches": 1,
    }
    base.update(overrides)
    return base


def _sample_ruleset(
    version: str = "1.0.0",
    rules: list[dict] | None = None,
) -> dict:
    """Return a valid rule-set payload."""
    return {
        "version": version,
        "rules": rules if rules is not None else [_sample_rule_dict()],
    }


def _write_ruleset(data_dir: Path, ruleset: dict, meta: dict | None = None) -> None:
    """Write a rule-set JSON and optional meta JSON into *data_dir*."""
    rules_file = data_dir / "custom_rules.json"
    rules_file.write_text(json.dumps(ruleset, indent=2))
    if meta is not None:
        meta_file = data_dir / "rules_meta.json"
        meta_file.write_text(json.dumps(meta, indent=2))


# ==================================================================
# TestRuleManager
# ==================================================================

class TestRuleManager:
    """Tests for RuleManager load, merge, update, and validation logic."""

    # -- load_custom_rules ---------------------------------------------

    def test_load_custom_rules_empty(self):
        """When no custom rules file exists, return an empty list."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            assert mgr.load_custom_rules() == []

    def test_load_custom_rules_valid(self):
        """Loading a well-formed JSON file returns MalwareRule instances."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            ruleset = _sample_ruleset(rules=[
                _sample_rule_dict(name="custom_a"),
                _sample_rule_dict(name="custom_b", severity="critical"),
            ])
            _write_ruleset(data_dir, ruleset)

            mgr = RuleManager(data_dir=data_dir)
            rules = mgr.load_custom_rules()

            assert len(rules) == 2
            assert all(isinstance(r, MalwareRule) for r in rules)
            assert rules[0].name == "custom_a"
            assert rules[0].severity == Severity.HIGH
            assert rules[1].name == "custom_b"
            assert rules[1].severity == Severity.CRITICAL

    # -- get_merged_rules ----------------------------------------------

    def test_get_merged_rules_no_custom(self):
        """With no custom rules, merged list equals BUILTIN_RULES."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            merged = mgr.get_merged_rules()
            assert len(merged) == len(BUILTIN_RULES)
            for builtin, merged_rule in zip(BUILTIN_RULES, merged):
                assert builtin.name == merged_rule.name

    def test_get_merged_rules_with_override(self):
        """A custom rule with the same name as a builtin replaces it."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            target = BUILTIN_RULES[0]
            override = _sample_rule_dict(
                name=target.name,
                severity="low",
                description="Overridden rule",
            )
            _write_ruleset(data_dir, _sample_ruleset(rules=[override]))

            mgr = RuleManager(data_dir=data_dir)
            merged = mgr.get_merged_rules()

            # Count must stay the same (replacement, not addition)
            assert len(merged) == len(BUILTIN_RULES)

            replaced = [r for r in merged if r.name == target.name]
            assert len(replaced) == 1
            assert replaced[0].severity == Severity.LOW
            assert replaced[0].description == "Overridden rule"

    def test_get_merged_rules_with_additions(self):
        """A custom rule with a new name is appended to the merged list."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            addition = _sample_rule_dict(name="brand_new_rule")
            _write_ruleset(data_dir, _sample_ruleset(rules=[addition]))

            mgr = RuleManager(data_dir=data_dir)
            merged = mgr.get_merged_rules()

            assert len(merged) == len(BUILTIN_RULES) + 1
            names = [r.name for r in merged]
            assert "brand_new_rule" in names

    # -- update_rules --------------------------------------------------

    def test_update_rules_success(self):
        """A successful HTTP fetch saves rules and meta files."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            mgr = RuleManager(data_dir=data_dir)

            ruleset = _sample_ruleset(version="2.0.0", rules=[
                _sample_rule_dict(name="remote_rule"),
            ])

            mock_resp = MagicMock()
            mock_resp.json.return_value = ruleset
            mock_resp.raise_for_status = MagicMock()

            with patch("scanners.rule_manager.requests.get", return_value=mock_resp):
                ok, msg = mgr.update_rules("https://example.com/rules.json")

            assert ok is True
            assert "2.0.0" in msg
            assert mgr.rules_file.exists()
            assert mgr.meta_file.exists()

            # Verify persisted content
            saved = json.loads(mgr.rules_file.read_text())
            assert saved["version"] == "2.0.0"
            assert len(saved["rules"]) == 1

    def test_update_rules_version_skip(self):
        """When the remote version matches the local version, skip update."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            ruleset = _sample_ruleset(version="1.5.0")
            meta = {
                "version": "1.5.0",
                "rule_count": 1,
                "last_updated": "2025-01-01T00:00:00+00:00",
                "source_url": "https://example.com/rules.json",
            }
            _write_ruleset(data_dir, ruleset, meta=meta)

            mgr = RuleManager(data_dir=data_dir)

            mock_resp = MagicMock()
            mock_resp.json.return_value = _sample_ruleset(version="1.5.0")
            mock_resp.raise_for_status = MagicMock()

            with patch("scanners.rule_manager.requests.get", return_value=mock_resp):
                ok, msg = mgr.update_rules("https://example.com/rules.json")

            assert ok is False
            assert "1.5.0" in msg

    def test_update_rules_invalid_json(self):
        """A response with invalid JSON returns an error."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))

            mock_resp = MagicMock()
            mock_resp.json.side_effect = ValueError("bad json")
            mock_resp.raise_for_status = MagicMock()

            with patch("scanners.rule_manager.requests.get", return_value=mock_resp):
                ok, msg = mgr.update_rules("https://example.com/rules.json")

            assert ok is False
            assert "Invalid JSON" in msg

    def test_update_rules_network_error(self):
        """A network failure returns an error tuple."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))

            with patch(
                "scanners.rule_manager.requests.get",
                side_effect=requests.ConnectionError("no route"),
            ):
                ok, msg = mgr.update_rules("https://unreachable.example.com/rules.json")

            assert ok is False
            assert "Network error" in msg

    # -- _validate_rules -----------------------------------------------

    def test_validate_rules_valid(self):
        """A well-formed rule-set passes validation."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            ok, err = mgr._validate_rules(_sample_ruleset())
            assert ok is True
            assert err == ""

    def test_validate_rules_missing_version(self):
        """Validation fails when 'version' is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            data = _sample_ruleset()
            del data["version"]
            ok, err = mgr._validate_rules(data)
            assert ok is False
            assert "version" in err.lower()

    def test_validate_rules_missing_fields(self):
        """Validation fails when a rule is missing required fields."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            bad_rule = {"name": "incomplete"}  # missing description, severity, category
            data = _sample_ruleset(rules=[bad_rule])
            ok, err = mgr._validate_rules(data)
            assert ok is False
            assert "missing" in err.lower()

    def test_validate_rules_invalid_severity(self):
        """Validation fails for an unrecognised severity value."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            bad_rule = _sample_rule_dict(severity="apocalyptic")
            data = _sample_ruleset(rules=[bad_rule])
            ok, err = mgr._validate_rules(data)
            assert ok is False
            assert "severity" in err.lower()

    # -- _dict_to_rule / _rule_to_dict roundtrip -----------------------

    def test_dict_to_rule_roundtrip(self):
        """Converting rule -> dict -> rule preserves all fields."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            original = MalwareRule(
                name="roundtrip_test",
                description="Tests serialisation round-trip",
                severity=Severity.MEDIUM,
                category="Test",
                string_patterns=["pattern_a", "pattern_b"],
                regex_patterns=[r"\d{4}-\d{2}"],
                file_extensions=[".exe", ".dll"],
                max_file_size=1024,
                min_matches=2,
            )

            d = mgr._rule_to_dict(original)
            restored = mgr._dict_to_rule(d)

            assert restored.name == original.name
            assert restored.description == original.description
            assert restored.severity == original.severity
            assert restored.category == original.category
            assert restored.string_patterns == original.string_patterns
            assert restored.regex_patterns == original.regex_patterns
            assert restored.file_extensions == original.file_extensions
            assert restored.max_file_size == original.max_file_size
            assert restored.min_matches == original.min_matches

    def test_dict_to_rule_byte_patterns(self):
        """Hex-encoded byte_patterns in JSON are converted to bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            rule_dict = _sample_rule_dict(
                byte_patterns=["90909090", "deadbeef"],
            )
            rule = mgr._dict_to_rule(rule_dict)

            assert rule.byte_patterns == [
                b"\x90\x90\x90\x90",
                b"\xde\xad\xbe\xef",
            ]

    # -- get_info ------------------------------------------------------

    def test_get_info_no_custom(self):
        """Without custom rules, info reflects builtins only."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = RuleManager(data_dir=Path(tmp))
            info = mgr.get_info()

            assert isinstance(info, RuleSetInfo)
            assert info.version == "builtin"
            assert info.rule_count == len(BUILTIN_RULES)
            assert info.source_url == ""

    def test_get_info_with_custom(self):
        """With custom rules, info contains version and merged count."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            ruleset = _sample_ruleset(version="3.0.0", rules=[
                _sample_rule_dict(name="extra_rule"),
            ])
            meta = {
                "version": "3.0.0",
                "rule_count": 1,
                "last_updated": "2025-06-15T12:00:00+00:00",
                "source_url": "https://example.com/rules.json",
            }
            _write_ruleset(data_dir, ruleset, meta=meta)

            mgr = RuleManager(data_dir=data_dir)
            info = mgr.get_info()

            assert info.version == "3.0.0"
            assert info.rule_count == len(BUILTIN_RULES) + 1
            assert info.last_updated == "2025-06-15T12:00:00+00:00"
            assert info.source_url == "https://example.com/rules.json"

    # -- _default_data_dir ---------------------------------------------

    def test_default_data_dir_windows(self):
        """On Windows the data dir is under AppData/Local."""
        with patch("scanners.rule_manager.platform.system", return_value="Windows"):
            path = RuleManager._default_data_dir()
            parts = path.parts
            assert "AppData" in parts
            assert "Local" in parts
            assert "Sentinel" in parts
            assert "rules" in parts

    def test_default_data_dir_macos(self):
        """On macOS the data dir is under Library/Application Support."""
        with patch("scanners.rule_manager.platform.system", return_value="Darwin"):
            path = RuleManager._default_data_dir()
            parts = path.parts
            assert "Library" in parts
            assert "Application Support" in parts
            assert "Sentinel" in parts
            assert "rules" in parts

    def test_default_data_dir_linux(self):
        """On Linux the data dir is under ~/.sentinel/rules."""
        with patch("scanners.rule_manager.platform.system", return_value="Linux"):
            path = RuleManager._default_data_dir()
            assert ".sentinel" in path.parts
            assert "rules" in path.parts
