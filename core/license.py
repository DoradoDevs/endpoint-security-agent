"""
Endpoint Security Agent — License & Edition Management

Manages optional license activation, feature gating, and trial periods.

This is an OPTIONAL, self-contained module. In this open-source build every
feature is available in the FREE edition — nothing in the agent is gated behind
a paid tier. The module is kept as a reference implementation for anyone who
wants to build an open-core distribution on top of the agent.

The HMAC key used to sign/verify license tokens is read from the
``ENDPOINT_AGENT_LICENSE_KEY`` environment variable so that no secret is baked
into the source. If it is unset, a public, non-secret development default is
used (fine for the open-source build, which does not gate any functionality).
If you ship a paid edition, set a strong random key via the environment and
keep it off the client machines that only need to verify.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


class LicenseEdition(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class LicenseToken:
    edition: LicenseEdition
    expiry_date: str  # ISO format date
    device_limit: int = 1
    issued_at: str = ""
    customer_id: str = ""
    signature: str = ""

    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expiry_date)
            return datetime.now() > expiry
        except (ValueError, TypeError):
            return True

    def to_dict(self) -> dict:
        return {
            "edition": self.edition.value,
            "expiry_date": self.expiry_date,
            "device_limit": self.device_limit,
            "issued_at": self.issued_at,
            "customer_id": self.customer_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> LicenseToken:
        return cls(
            edition=LicenseEdition(data.get("edition", "free")),
            expiry_date=data.get("expiry_date", ""),
            device_limit=data.get("device_limit", 1),
            issued_at=data.get("issued_at", ""),
            customer_id=data.get("customer_id", ""),
            signature=data.get("signature", ""),
        )


class LicenseManager:
    """Manages license activation, validation, and feature gating.

    The signing key is loaded from the environment rather than hardcoded so no
    secret ships in the source tree. See the module docstring for details.
    """

    # HMAC key for license-token signature verification. Loaded from the
    # environment; falls back to a public, non-secret default for the
    # open-source build (which does not gate any functionality behind a tier).
    _SIGNING_KEY = os.environ.get(
        "ENDPOINT_AGENT_LICENSE_KEY",
        "public-development-key-not-secret",
    ).encode()

    def __init__(self, license_dir: Path | None = None):
        self._license_dir = license_dir or self._default_license_dir()
        self._license_dir.mkdir(parents=True, exist_ok=True)
        self._license_file = self._license_dir / "license.json"
        self._trial_file = self._license_dir / "trial.json"
        self._cached_token: LicenseToken | None = None

    @staticmethod
    def _default_license_dir() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "license"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "license"
        else:
            return Path.home() / ".sentinel" / "license"

    def activate(self, license_key: str) -> tuple[bool, str]:
        """Activate a license key. Key is base64-encoded JSON with HMAC signature."""
        try:
            decoded = base64.b64decode(license_key)
            data = json.loads(decoded)
        except Exception:
            return False, "Invalid license key format"

        # Verify signature
        signature = data.pop("signature", "")
        payload = json.dumps(data, sort_keys=True).encode()
        expected_sig = hmac.new(self._SIGNING_KEY, payload, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid license signature"

        data["signature"] = signature
        token = LicenseToken.from_dict(data)

        if token.is_expired():
            return False, f"License expired on {token.expiry_date}"

        # Save license
        self._license_file.write_text(json.dumps(token.to_dict(), indent=2))
        self._cached_token = token

        return True, f"License activated: {token.edition.value.upper()} (expires {token.expiry_date})"

    def deactivate(self) -> tuple[bool, str]:
        """Remove the active license."""
        if self._license_file.exists():
            self._license_file.unlink()
            self._cached_token = None
            return True, "License deactivated"
        return False, "No active license found"

    def get_current_edition(self) -> LicenseEdition:
        """Get the current license edition (checks license validity + trial)."""
        # Check active license
        token = self._load_license()
        if token and not token.is_expired():
            return token.edition

        # Check trial
        if self.check_trial():
            return LicenseEdition.PRO

        return LicenseEdition.FREE

    def is_pro_feature_available(self) -> bool:
        """Check if Pro features are available (Pro/Enterprise license or active trial)."""
        edition = self.get_current_edition()
        return edition in (LicenseEdition.PRO, LicenseEdition.ENTERPRISE)

    def check_trial(self) -> bool:
        """Check if the 14-day Pro trial is still active."""
        if not self._trial_file.exists():
            return False
        try:
            data = json.loads(self._trial_file.read_text())
            start_date = datetime.fromisoformat(data["trial_start"])
            return datetime.now() < start_date + timedelta(days=14)
        except (json.JSONDecodeError, KeyError, ValueError):
            return False

    def start_trial(self) -> tuple[bool, str]:
        """Start a 14-day Pro trial."""
        if self._trial_file.exists():
            try:
                data = json.loads(self._trial_file.read_text())
                if "trial_start" in data:
                    start = datetime.fromisoformat(data["trial_start"])
                    if datetime.now() < start + timedelta(days=14):
                        remaining = 14 - (datetime.now() - start).days
                        return False, f"Trial already active ({remaining} days remaining)"
                    return False, "Trial period has expired"
            except (json.JSONDecodeError, ValueError):
                pass

        trial_data = {
            "trial_start": datetime.now().isoformat(),
            "device_id": self._get_device_id(),
        }
        self._trial_file.write_text(json.dumps(trial_data, indent=2))
        return True, "14-day Pro trial started!"

    def get_license_info(self) -> dict[str, Any]:
        """Get full license status information."""
        edition = self.get_current_edition()
        token = self._load_license()
        trial_active = self.check_trial()

        info = {
            "edition": edition.value,
            "pro_available": self.is_pro_feature_available(),
            "trial_active": trial_active,
            "license_active": token is not None and not token.is_expired(),
        }

        if token:
            info["expiry_date"] = token.expiry_date
            info["customer_id"] = token.customer_id
            info["device_limit"] = token.device_limit

        if trial_active:
            try:
                data = json.loads(self._trial_file.read_text())
                start = datetime.fromisoformat(data["trial_start"])
                remaining = 14 - (datetime.now() - start).days
                info["trial_days_remaining"] = max(0, remaining)
            except Exception:
                pass

        return info

    def _load_license(self) -> LicenseToken | None:
        """Load and cache the license token."""
        if self._cached_token is not None:
            return self._cached_token
        if not self._license_file.exists():
            return None
        try:
            data = json.loads(self._license_file.read_text())
            self._cached_token = LicenseToken.from_dict(data)
            return self._cached_token
        except (json.JSONDecodeError, KeyError):
            return None

    @staticmethod
    def _get_device_id() -> str:
        """Generate a device-unique identifier."""
        parts = [platform.node(), platform.system(), platform.machine()]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @classmethod
    def generate_license_key(cls, edition: LicenseEdition, expiry_date: str,
                              customer_id: str = "", device_limit: int = 1) -> str:
        """Generate a signed license key (for testing and admin use)."""
        data = {
            "edition": edition.value,
            "expiry_date": expiry_date,
            "device_limit": device_limit,
            "issued_at": datetime.now().isoformat(),
            "customer_id": customer_id,
        }
        payload = json.dumps(data, sort_keys=True).encode()
        signature = hmac.new(cls._SIGNING_KEY, payload, hashlib.sha256).hexdigest()
        data["signature"] = signature
        return base64.b64encode(json.dumps(data).encode()).decode()


def require_pro(func):
    """Decorator to gate Pro features."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        mgr = LicenseManager()
        if not mgr.is_pro_feature_available():
            raise PermissionError(
                f"'{func.__name__}' requires Sentinel Pro. "
                "Activate a license with --activate <key> or start a trial with --start-trial"
            )
        return func(*args, **kwargs)
    return wrapper
