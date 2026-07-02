"""Tests for the security profiles system."""

import json
import tempfile
from pathlib import Path

from core.config import ScanDepth, Severity, ScanConfig
from core.profiles import (
    SecurityProfile,
    ProfileSpec,
    BUILTIN_PROFILES,
    get_profile,
    load_custom_profile,
    save_custom_profile,
    list_profiles,
)


def test_all_builtin_profiles_exist():
    """Verify all expected profiles are defined."""
    expected = {SecurityProfile.MINIMAL, SecurityProfile.STANDARD,
                SecurityProfile.STRICT, SecurityProfile.FORT_KNOX}
    assert expected == set(BUILTIN_PROFILES.keys())


def test_profiles_produce_valid_scan_config():
    """Every profile should produce a valid ScanConfig."""
    for profile_enum, spec in BUILTIN_PROFILES.items():
        scan_config = spec.to_scan_config()
        assert isinstance(scan_config, ScanConfig)
        assert isinstance(scan_config.depth, ScanDepth)


def test_minimal_profile_is_light():
    """Minimal profile should disable optional scanners."""
    spec = BUILTIN_PROFILES[SecurityProfile.MINIMAL]
    assert spec.scan_depth == ScanDepth.QUICK
    assert spec.min_severity == Severity.HIGH
    assert not spec.enable_startup_scan
    assert not spec.enable_package_scan
    assert not spec.enable_cve_lookup
    assert not spec.enable_hardening


def test_fort_knox_enables_everything():
    """Fort Knox should enable all scanners and auto-remediation."""
    spec = BUILTIN_PROFILES[SecurityProfile.FORT_KNOX]
    assert spec.scan_depth == ScanDepth.DEEP
    assert spec.min_severity == Severity.INFO
    assert spec.enable_hardening
    assert spec.auto_remediate
    assert spec.enable_continuous_monitoring
    assert spec.enable_file_integrity_scan
    assert spec.enable_browser_scan
    assert spec.enable_credential_scan
    assert spec.enable_log_analysis_scan
    assert spec.enable_privilege_scan
    assert spec.enable_service_audit_scan


def test_profile_serialization_roundtrip():
    """Profile should survive to_dict -> from_dict."""
    spec = BUILTIN_PROFILES[SecurityProfile.STRICT]
    data = spec.to_dict()
    restored = ProfileSpec.from_dict(data)
    assert restored.name == spec.name
    assert restored.scan_depth == spec.scan_depth
    assert restored.min_severity == spec.min_severity
    assert restored.enable_file_integrity_scan == spec.enable_file_integrity_scan


def test_custom_profile_save_load():
    """Custom profile JSON save and load should round-trip."""
    spec = ProfileSpec(
        name="My Custom",
        description="Test custom profile",
        scan_depth=ScanDepth.STANDARD,
        enable_process_scan=True,
        enable_network_scan=False,
        enable_startup_scan=True,
        enable_package_scan=False,
        enable_config_scan=True,
        enable_cve_lookup=False,
        min_severity=Severity.MEDIUM,
    )
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        path = Path(f.name)

    try:
        save_custom_profile(spec, path)
        loaded = load_custom_profile(path)
        assert loaded.name == "My Custom"
        assert loaded.scan_depth == ScanDepth.STANDARD
        assert loaded.min_severity == Severity.MEDIUM
        assert not loaded.enable_network_scan
    finally:
        path.unlink(missing_ok=True)


def test_get_profile_builtin():
    """get_profile should return correct built-in profile."""
    spec = get_profile(SecurityProfile.STANDARD)
    assert spec.name == "Standard"


def test_get_profile_custom_requires_path():
    """Custom profile without path should raise ValueError."""
    try:
        get_profile(SecurityProfile.CUSTOM, custom_path=None)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_severity_filter_in_scan_config():
    """Profile's min_severity should propagate to ScanConfig."""
    spec = BUILTIN_PROFILES[SecurityProfile.MINIMAL]
    scan_config = spec.to_scan_config()
    assert scan_config.min_severity == "high"


def test_list_profiles_returns_all():
    """list_profiles should return info for all built-in profiles."""
    summaries = list_profiles()
    assert len(summaries) == len(BUILTIN_PROFILES)
    ids = [s["id"] for s in summaries]
    assert "minimal" in ids
    assert "fort_knox" in ids


def test_auto_mode_from_fort_knox():
    """Fort Knox profile should set auto_mode in ScanConfig."""
    spec = BUILTIN_PROFILES[SecurityProfile.FORT_KNOX]
    scan_config = spec.to_scan_config()
    assert scan_config.auto_mode is True


def test_standard_no_auto_mode():
    """Standard profile should not set auto_mode."""
    spec = BUILTIN_PROFILES[SecurityProfile.STANDARD]
    scan_config = spec.to_scan_config()
    assert scan_config.auto_mode is False


if __name__ == "__main__":
    test_all_builtin_profiles_exist()
    test_profiles_produce_valid_scan_config()
    test_minimal_profile_is_light()
    test_fort_knox_enables_everything()
    test_profile_serialization_roundtrip()
    test_custom_profile_save_load()
    test_get_profile_builtin()
    test_get_profile_custom_requires_path()
    test_severity_filter_in_scan_config()
    test_list_profiles_returns_all()
    test_auto_mode_from_fort_knox()
    test_standard_no_auto_mode()
    print("All profile tests passed!")
