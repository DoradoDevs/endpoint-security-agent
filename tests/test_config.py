"""Tests for configuration module."""

import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import AgentConfig, ScanConfig, ScanDepth, Severity


def test_default_config():
    config = AgentConfig()
    assert config.scan.depth == ScanDepth.STANDARD
    assert config.scan.dry_run is False
    assert config.scan.auto_mode is False
    assert config.version == "4.0.0"


def test_config_serialization():
    config = AgentConfig()
    data = config.to_dict()
    assert "scan" in data
    assert "report" in data
    assert data["scan"]["depth"] == "standard"


def test_config_save_load():
    config = AgentConfig()
    config.scan.depth = ScanDepth.DEEP
    config.scan.dry_run = True

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        tmppath = Path(f.name)

    try:
        config.save(tmppath)
        loaded = AgentConfig.load(tmppath)
        assert loaded.scan.depth == ScanDepth.DEEP
        assert loaded.scan.dry_run is True
    finally:
        tmppath.unlink(missing_ok=True)


def test_severity_weights():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight
    assert Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight
    assert Severity.LOW.weight > Severity.INFO.weight
    assert Severity.INFO.weight == 0.0


if __name__ == "__main__":
    test_default_config()
    test_config_serialization()
    test_config_save_load()
    test_severity_weights()
    print("All config tests passed!")
