"""
Sentinel Fleet — Agent Registration

Handles device identification, enrollment tokens, and server handshake
for fleet-managed deployments. All fleet communication is opt-in.
"""

from __future__ import annotations

import hashlib
import json
import platform
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.logging import get_logger


@dataclass
class DeviceIdentity:
    """Unique device identity for fleet registration."""

    device_id: str = ""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    architecture: str = ""
    agent_version: str = ""
    enrolled_at: str = ""
    last_seen: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EnrollmentResult:
    """Result of a fleet enrollment attempt."""

    success: bool = False
    device_id: str = ""
    message: str = ""
    server_policies: dict[str, Any] = field(default_factory=dict)


def _sentinel_data_dir() -> Path:
    """Get the Sentinel data directory for the current platform."""
    system = platform.system().lower()
    if system == "windows":
        base = Path.home() / "AppData" / "Local" / "Sentinel"
    elif system == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Sentinel"
    else:
        base = Path.home() / ".sentinel"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _generate_device_id() -> str:
    """Generate a stable device ID based on hardware characteristics."""
    components = [
        platform.node(),
        platform.machine(),
        platform.system(),
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AgentRegistration:
    """Manages device registration with a fleet server."""

    def __init__(self, server_url: str = "", enrollment_token: str = ""):
        self.server_url = server_url.rstrip("/")
        self.enrollment_token = enrollment_token
        self.log = get_logger()
        self._data_dir = _sentinel_data_dir()
        self._identity_file = self._data_dir / "device_identity.json"

    @property
    def device_id(self) -> str:
        """Get or generate the device ID."""
        identity = self.load_identity()
        if identity and identity.device_id:
            return identity.device_id
        return _generate_device_id()

    def load_identity(self) -> DeviceIdentity | None:
        """Load saved device identity from disk."""
        if not self._identity_file.exists():
            return None
        try:
            data = json.loads(self._identity_file.read_text())
            return DeviceIdentity(**data)
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            self.log.warning(f"Failed to load device identity: {e}")
            return None

    def save_identity(self, identity: DeviceIdentity) -> None:
        """Save device identity to disk."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._identity_file.write_text(json.dumps(identity.to_dict(), indent=2))
        self.log.info(f"Device identity saved: {identity.device_id}")

    def create_identity(self, agent_version: str = "2.0.0") -> DeviceIdentity:
        """Create a new device identity from current system info."""
        now = datetime.now(timezone.utc).isoformat()
        identity = DeviceIdentity(
            device_id=_generate_device_id(),
            hostname=platform.node(),
            os_name=platform.system(),
            os_version=platform.version(),
            architecture=platform.machine(),
            agent_version=agent_version,
            enrolled_at=now,
            last_seen=now,
        )
        return identity

    def enroll(self, agent_version: str = "2.0.0") -> EnrollmentResult:
        """Enroll this device with the fleet server.

        Returns EnrollmentResult with success status and any server policies.
        """
        if not self.server_url:
            return EnrollmentResult(
                success=False,
                message="No fleet server URL configured",
            )

        if not self.enrollment_token:
            return EnrollmentResult(
                success=False,
                message="No enrollment token provided",
            )

        identity = self.create_identity(agent_version)

        # Build enrollment payload
        payload = {
            "device_id": identity.device_id,
            "hostname": identity.hostname,
            "os_name": identity.os_name,
            "os_version": identity.os_version,
            "architecture": identity.architecture,
            "agent_version": identity.agent_version,
            "enrollment_token": self.enrollment_token,
        }

        try:
            import urllib.request
            import urllib.error

            url = f"{self.server_url}/api/v1/devices/enroll"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.enrollment_token}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                response_data = json.loads(resp.read().decode())

            identity.enrolled_at = datetime.now(timezone.utc).isoformat()
            identity.last_seen = identity.enrolled_at
            self.save_identity(identity)

            return EnrollmentResult(
                success=True,
                device_id=identity.device_id,
                message="Successfully enrolled with fleet server",
                server_policies=response_data.get("policies", {}),
            )

        except urllib.error.URLError as e:
            self.log.error(f"Fleet enrollment failed: {e}")
            return EnrollmentResult(
                success=False,
                device_id=identity.device_id,
                message=f"Connection failed: {e}",
            )
        except Exception as e:
            self.log.error(f"Fleet enrollment error: {e}")
            return EnrollmentResult(
                success=False,
                device_id=identity.device_id,
                message=f"Enrollment error: {e}",
            )

    def update_last_seen(self) -> None:
        """Update the last_seen timestamp for this device."""
        identity = self.load_identity()
        if identity:
            identity.last_seen = datetime.now(timezone.utc).isoformat()
            self.save_identity(identity)

    def is_enrolled(self) -> bool:
        """Check if this device is enrolled with a fleet server."""
        identity = self.load_identity()
        return identity is not None and bool(identity.enrolled_at)
