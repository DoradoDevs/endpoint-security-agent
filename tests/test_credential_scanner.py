"""Tests for Credential Scanner."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from core.config import AgentConfig, ScanDepth, Severity
from scanners.credential_scanner import CredentialScanner


def _make_config(depth=ScanDepth.STANDARD):
    config = AgentConfig()
    config.scan.depth = depth
    return config


def test_scanner_properties():
    scanner = CredentialScanner(_make_config())
    assert scanner.name == "Credential Scanner"
    assert "all" in scanner.supported_platforms


def test_env_file_with_secrets_detected():
    """A .env file containing secrets should produce HIGH finding."""
    scanner = CredentialScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        env_file = home / ".env"
        env_file.write_text("API_KEY=sk_live_abcdef123456\nDB_PASSWORD=secret123\n")

        findings = scanner._check_credential_files(home)
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert "secrets" in high[0].title.lower() or ".env" in high[0].title


def test_no_credential_files_is_clean():
    """Empty home directory should produce no credential findings."""
    scanner = CredentialScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        findings = scanner._check_credential_files(home)
        assert len(findings) == 0


def test_cloud_credentials_detected():
    """Cloud credential files should be flagged."""
    scanner = CredentialScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        aws_dir = home / ".aws"
        aws_dir.mkdir()
        (aws_dir / "credentials").write_text("[default]\naws_access_key_id=AKIA...\n")

        findings = scanner._check_cloud_credentials(home)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM
        assert "cloud" in findings[0].title.lower() or "aws" in findings[0].evidence.get("provider", "").lower()


def test_ssh_key_detection():
    """SSH private key check should produce findings."""
    scanner = CredentialScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir()
        # Create a fake unencrypted SSH key
        (ssh_dir / "id_rsa").write_bytes(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nnone\nfake key data\n"
            b"-----END OPENSSH PRIVATE KEY-----\n"
        )

        findings = scanner._check_ssh_keys(home)
        assert len(findings) >= 1


def test_never_logs_actual_secrets():
    """Credential scanner should never include actual secret values in evidence."""
    scanner = CredentialScanner(_make_config())

    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        env_file = home / ".env"
        secret_value = "super_secret_password_12345"
        env_file.write_text(f"PASSWORD={secret_value}\n")

        findings = scanner._check_credential_files(home)
        for finding in findings:
            evidence_str = str(finding.evidence)
            assert secret_value not in evidence_str, \
                "Actual secret value must never appear in finding evidence"


if __name__ == "__main__":
    test_scanner_properties()
    test_env_file_with_secrets_detected()
    test_no_credential_files_is_clean()
    test_cloud_credentials_detected()
    test_ssh_key_detection()
    test_never_logs_actual_secrets()
    print("All credential scanner tests passed!")
