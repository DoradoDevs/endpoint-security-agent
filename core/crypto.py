"""Sentinel Agent — Cryptographic Utilities

Key derivation and authenticated encryption for audit log protection.
Uses only stdlib (hashlib, hmac) for hash chain. Optional AES requires cryptography lib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any


def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from a passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: User-supplied passphrase.
        salt: Optional 16-byte salt. Generated randomly if *None*.

    Returns:
        Tuple of (32-byte derived key, salt used).
    """
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations=100_000)
    return key, salt


def hmac_sha256(key: bytes, data: str) -> str:
    """Compute HMAC-SHA256 hex digest.

    Args:
        key: Secret key bytes.
        data: String payload to authenticate.

    Returns:
        Hex-encoded HMAC digest.
    """
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_chain_hash(previous_hash: str, entry_data: str) -> str:
    """Compute the next link in a hash chain.

    ``H(previous_hash || ':' || entry_data)`` using SHA-256.

    Args:
        previous_hash: Hex digest of the previous entry.
        entry_data: Serialised payload of the current entry.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    combined = f"{previous_hash}:{entry_data}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Optional AES-256-GCM encryption (requires ``cryptography`` library)
# ---------------------------------------------------------------------------

def encrypt_entry(key: bytes, plaintext: str) -> dict[str, str]:
    """Encrypt an entry using AES-256-GCM.

    If the ``cryptography`` library is not installed the plaintext is returned
    as-is with ``"encrypted": False``.

    Args:
        key: 32-byte encryption key.
        plaintext: Data to encrypt.

    Returns:
        Dict with *iv*, *ciphertext*, and *encrypted* flag (or *plaintext*
        when encryption is unavailable).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        return {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "encrypted": True,
        }
    except ImportError:
        return {"plaintext": plaintext, "encrypted": False}


def decrypt_entry(key: bytes, entry: dict[str, Any]) -> str:
    """Decrypt an AES-256-GCM encrypted entry.

    Args:
        key: 32-byte encryption key (must match the key used to encrypt).
        entry: Dict previously returned by :func:`encrypt_entry`.

    Returns:
        Decrypted plaintext string.

    Raises:
        RuntimeError: If ``cryptography`` is required but not installed.
    """
    if not entry.get("encrypted", False):
        return entry.get("plaintext", "")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        iv = base64.b64decode(entry["iv"])
        ct = base64.b64decode(entry["ciphertext"])
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ct, None).decode("utf-8")
    except ImportError:
        raise RuntimeError("cryptography library required for decryption")
