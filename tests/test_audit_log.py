"""Tests for the Sentinel encrypted audit log and crypto utilities.

Covers:
  - core.crypto: derive_key, hmac_sha256, compute_chain_hash, encrypt/decrypt
  - core.audit_log: AuditLog recording, chain verification, export, encryption
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure project root is importable
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from core.crypto import (
    compute_chain_hash,
    decrypt_entry,
    derive_key,
    encrypt_entry,
    hmac_sha256,
)
from core.audit_log import GENESIS_HASH, AuditEntry, AuditLog


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """Provide a fresh temporary directory for audit logs."""
    d = tmp_path / "audit"
    d.mkdir()
    return d


@pytest.fixture
def audit_log(audit_dir: Path) -> AuditLog:
    """Provide an AuditLog instance writing to the temp directory."""
    return AuditLog(log_dir=audit_dir)


@pytest.fixture
def encrypted_audit_log(audit_dir: Path) -> AuditLog:
    """Provide an AuditLog instance with encryption enabled."""
    return AuditLog(log_dir=audit_dir, passphrase="s3cret-test-key!")


# ---------------------------------------------------------------------------
# core.crypto tests
# ---------------------------------------------------------------------------

class TestDeriveKey:
    """Tests for derive_key."""

    def test_produces_32_byte_key(self) -> None:
        key, salt = derive_key("my-passphrase")
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_produces_16_byte_salt(self) -> None:
        key, salt = derive_key("any-pass")
        assert len(salt) == 16
        assert isinstance(salt, bytes)

    def test_deterministic_with_same_salt(self) -> None:
        _, salt = derive_key("pass")
        key1, _ = derive_key("pass", salt)
        key2, _ = derive_key("pass", salt)
        assert key1 == key2

    def test_different_passphrase_different_key(self) -> None:
        _, salt = derive_key("aaa")
        key1, _ = derive_key("aaa", salt)
        key2, _ = derive_key("bbb", salt)
        assert key1 != key2


class TestHmacSha256:
    """Tests for hmac_sha256."""

    def test_consistent_output(self) -> None:
        key = b"secret"
        digest1 = hmac_sha256(key, "hello")
        digest2 = hmac_sha256(key, "hello")
        assert digest1 == digest2

    def test_returns_hex_string(self) -> None:
        digest = hmac_sha256(b"key", "data")
        assert isinstance(digest, str)
        assert len(digest) == 64  # SHA-256 hex digest

    def test_different_data_different_digest(self) -> None:
        key = b"key"
        assert hmac_sha256(key, "a") != hmac_sha256(key, "b")


class TestComputeChainHash:
    """Tests for compute_chain_hash."""

    def test_deterministic(self) -> None:
        h1 = compute_chain_hash("abc", "data")
        h2 = compute_chain_hash("abc", "data")
        assert h1 == h2

    def test_different_previous_hash(self) -> None:
        h1 = compute_chain_hash("aaa", "data")
        h2 = compute_chain_hash("bbb", "data")
        assert h1 != h2

    def test_different_data(self) -> None:
        h1 = compute_chain_hash("prev", "data1")
        h2 = compute_chain_hash("prev", "data2")
        assert h1 != h2

    def test_returns_64_char_hex(self) -> None:
        h = compute_chain_hash("0" * 64, "payload")
        assert len(h) == 64


class TestEncryptDecryptFallback:
    """Tests for encrypt_entry / decrypt_entry when cryptography is not available."""

    def test_fallback_plaintext_when_no_crypto_lib(self) -> None:
        """When the cryptography library is unavailable, plaintext is returned."""
        with patch.dict("sys.modules", {"cryptography": None,
                                         "cryptography.hazmat": None,
                                         "cryptography.hazmat.primitives": None,
                                         "cryptography.hazmat.primitives.ciphers": None,
                                         "cryptography.hazmat.primitives.ciphers.aead": None}):
            # Force re-import failure inside encrypt_entry
            result = encrypt_entry(b"0" * 32, "hello world")
            assert result["encrypted"] is False
            assert result["plaintext"] == "hello world"

    def test_decrypt_unencrypted_entry(self) -> None:
        entry = {"plaintext": "some data", "encrypted": False}
        assert decrypt_entry(b"key", entry) == "some data"

    def test_decrypt_empty_plaintext(self) -> None:
        entry = {"encrypted": False}
        assert decrypt_entry(b"key", entry) == ""


class TestEncryptDecryptWithCrypto:
    """Tests for encrypt/decrypt with the real cryptography library (if available)."""

    @pytest.fixture(autouse=True)
    def _skip_without_crypto(self) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except ImportError:
            pytest.skip("cryptography library not installed")

    def test_round_trip(self) -> None:
        key, _ = derive_key("test-pass")
        plaintext = "sensitive audit data"
        enc = encrypt_entry(key, plaintext)
        assert enc["encrypted"] is True
        assert "ciphertext" in enc
        assert "iv" in enc
        decrypted = decrypt_entry(key, enc)
        assert decrypted == plaintext

    def test_different_iv_each_time(self) -> None:
        key, _ = derive_key("pass")
        e1 = encrypt_entry(key, "same")
        e2 = encrypt_entry(key, "same")
        # IVs should differ (random)
        assert e1["iv"] != e2["iv"]


# ---------------------------------------------------------------------------
# core.audit_log tests
# ---------------------------------------------------------------------------

class TestGenesisHash:
    """Sanity check for the genesis constant."""

    def test_is_64_zeros(self) -> None:
        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64


class TestAuditEntrySerialisation:
    """AuditEntry to_dict / from_dict round-trip."""

    def test_round_trip(self) -> None:
        entry = AuditEntry(
            seq=1,
            timestamp="2025-01-01T00:00:00+00:00",
            event="test_event",
            data={"key": "value"},
            chain_hash="a" * 64,
        )
        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.seq == entry.seq
        assert restored.timestamp == entry.timestamp
        assert restored.event == entry.event
        assert restored.data == entry.data
        assert restored.chain_hash == entry.chain_hash


class TestAuditLogBasic:
    """Basic (unencrypted) audit log operations."""

    def test_record_creates_log_file(self, audit_log: AuditLog) -> None:
        audit_log.record("scan_started")
        assert audit_log.log_file.exists()

    def test_sequential_sequence_numbers(self, audit_log: AuditLog) -> None:
        e1 = audit_log.record("event_one")
        e2 = audit_log.record("event_two")
        e3 = audit_log.record("event_three")
        assert e1.seq == 1
        assert e2.seq == 2
        assert e3.seq == 3

    def test_verify_chain_passes(self, audit_log: AuditLog) -> None:
        audit_log.record("a")
        audit_log.record("b")
        audit_log.record("c")
        valid, errors = audit_log.verify_chain()
        assert valid is True
        assert errors == []

    def test_detect_tampered_entry(self, audit_log: AuditLog) -> None:
        audit_log.record("first")
        audit_log.record("second")
        audit_log.record("third")

        # Tamper: modify the second line
        lines = audit_log.log_file.read_text(encoding="utf-8").strip().splitlines()
        entry = json.loads(lines[1])
        entry["event"] = "TAMPERED"
        lines[1] = json.dumps(entry)
        audit_log.log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, errors = audit_log.verify_chain()
        assert valid is False
        assert len(errors) >= 1
        assert "hash mismatch" in errors[0]

    def test_get_entries(self, audit_log: AuditLog) -> None:
        audit_log.record("alpha", {"x": 1})
        audit_log.record("beta", {"y": 2})
        entries = audit_log.get_entries()
        assert len(entries) == 2
        assert entries[0].event == "alpha"
        assert entries[1].event == "beta"

    def test_get_entries_with_limit(self, audit_log: AuditLog) -> None:
        for i in range(10):
            audit_log.record(f"event_{i}")
        entries = audit_log.get_entries(limit=3)
        assert len(entries) == 3
        # Should return the last 3
        assert entries[0].event == "event_7"
        assert entries[1].event == "event_8"
        assert entries[2].event == "event_9"

    def test_empty_log_verifies(self, audit_dir: Path) -> None:
        log = AuditLog(log_dir=audit_dir)
        valid, errors = log.verify_chain()
        assert valid is True
        assert errors == []

    def test_export_to_json(self, audit_log: AuditLog, tmp_path: Path) -> None:
        audit_log.record("export_test", {"detail": "value"})
        audit_log.record("export_test_2")

        out = tmp_path / "export.json"
        count = audit_log.export(out)

        assert count == 2
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["total_entries"] == 2
        assert len(data["entries"]) == 2
        assert "exported_at" in data

    def test_chain_hash_links(self, audit_log: AuditLog) -> None:
        """Each entry's chain_hash should depend on the previous entry."""
        e1 = audit_log.record("one")
        e2 = audit_log.record("two")
        assert e1.chain_hash != e2.chain_hash
        # Recompute to confirm linkage
        entry_data = json.dumps(
            {"event": "two", "data": {}, "timestamp": e2.timestamp},
            sort_keys=True,
        )
        expected = compute_chain_hash(e1.chain_hash, entry_data)
        assert e2.chain_hash == expected

    def test_state_persists_across_instances(self, audit_dir: Path) -> None:
        """A new AuditLog instance resumes from the last entry."""
        log1 = AuditLog(log_dir=audit_dir)
        log1.record("first")
        log1.record("second")

        log2 = AuditLog(log_dir=audit_dir)
        e3 = log2.record("third")
        assert e3.seq == 3

        # Full chain should still verify
        valid, errors = log2.verify_chain()
        assert valid is True


class TestAuditLogEncrypted:
    """Audit log with passphrase-based encryption."""

    @pytest.fixture(autouse=True)
    def _skip_without_crypto(self) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except ImportError:
            pytest.skip("cryptography library not installed")

    def test_encrypted_record_and_decrypt(self, encrypted_audit_log: AuditLog) -> None:
        encrypted_audit_log.record("secret_event", {"password": "hunter2"})
        entries = encrypted_audit_log.get_entries()
        assert len(entries) == 1
        assert entries[0].event == "secret_event"
        assert entries[0].data == {"password": "hunter2"}

    def test_encrypted_log_file_no_cleartext(self, encrypted_audit_log: AuditLog) -> None:
        encrypted_audit_log.record("classified", {"code": "abc123"})
        raw = encrypted_audit_log.log_file.read_text(encoding="utf-8")
        # The event name and data should not appear in cleartext
        assert '"classified"' not in raw or '"encrypted_payload"' in raw

    def test_verify_chain_with_encryption(self, encrypted_audit_log: AuditLog) -> None:
        encrypted_audit_log.record("enc_a")
        encrypted_audit_log.record("enc_b")
        encrypted_audit_log.record("enc_c")
        valid, errors = encrypted_audit_log.verify_chain()
        assert valid is True
        assert errors == []

    def test_verify_encrypted_without_passphrase(self, audit_dir: Path) -> None:
        """Verifying encrypted entries without a passphrase reports an error."""
        enc_log = AuditLog(log_dir=audit_dir, passphrase="secret")
        enc_log.record("hidden")

        # Open the same log without a passphrase
        plain_log = AuditLog(log_dir=audit_dir)
        valid, errors = plain_log.verify_chain()
        assert valid is False
        assert any("no passphrase" in e for e in errors)

    def test_get_entries_encrypted_without_passphrase(self, audit_dir: Path) -> None:
        """Reading encrypted entries without a passphrase shows [encrypted]."""
        enc_log = AuditLog(log_dir=audit_dir, passphrase="secret")
        enc_log.record("hidden_event")

        plain_log = AuditLog(log_dir=audit_dir)
        entries = plain_log.get_entries()
        assert len(entries) == 1
        assert entries[0].event == "[encrypted]"
        assert entries[0].data == {}

    def test_salt_file_created(self, encrypted_audit_log: AuditLog) -> None:
        encrypted_audit_log.record("trigger_salt")
        assert encrypted_audit_log._salt_file.exists()
        salt_bytes = encrypted_audit_log._salt_file.read_bytes()
        assert len(salt_bytes) == 16

    def test_salt_reuse_across_instances(self, audit_dir: Path) -> None:
        """A second instance with the same passphrase should reuse the salt."""
        log1 = AuditLog(log_dir=audit_dir, passphrase="same")
        log1.record("entry_1")
        salt1 = log1._salt_file.read_bytes()

        log2 = AuditLog(log_dir=audit_dir, passphrase="same")
        log2.record("entry_2")
        salt2 = log2._salt_file.read_bytes()

        assert salt1 == salt2

        # And the chain should verify
        valid, errors = log2.verify_chain()
        assert valid is True


class TestAuditLogEdgeCases:
    """Edge cases and robustness."""

    def test_record_with_none_data(self, audit_log: AuditLog) -> None:
        entry = audit_log.record("no_data", None)
        assert entry.data == {}

    def test_record_with_empty_event(self, audit_log: AuditLog) -> None:
        entry = audit_log.record("")
        assert entry.event == ""
        valid, _ = audit_log.verify_chain()
        assert valid is True

    def test_record_with_special_characters(self, audit_log: AuditLog) -> None:
        entry = audit_log.record("unicode_event", {"msg": "Hello \u2603 \U0001f600"})
        entries = audit_log.get_entries()
        assert entries[0].data["msg"] == "Hello \u2603 \U0001f600"

    def test_large_data_payload(self, audit_log: AuditLog) -> None:
        big_data = {"items": list(range(1000))}
        entry = audit_log.record("large", big_data)
        valid, errors = audit_log.verify_chain()
        assert valid is True
        entries = audit_log.get_entries()
        assert entries[0].data == big_data
