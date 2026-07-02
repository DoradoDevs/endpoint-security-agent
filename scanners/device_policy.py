"""
Sentinel Agent — Device Policy

Defines and enforces policies for USB and Bluetooth device usage.
Policies control which devices are allowed, blocked, and how many
connections are acceptable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanners.device_inventory import DeviceInfo


@dataclass
class DevicePolicy:
    """Policy for allowed/blocked devices."""

    block_usb_storage: bool = False
    max_usb_devices: int = 20
    max_bluetooth_devices: int = 10
    allowed_usb_vendors: list[str] = field(default_factory=list)
    blocked_usb_vendors: list[str] = field(default_factory=list)
    block_bluetooth: bool = False

    def check_device(self, device: DeviceInfo) -> tuple[bool, str]:
        """Check if a device complies with this policy.

        Returns:
            Tuple of (compliant: bool, reason: str).
            If compliant is True, reason is empty.
        """
        # Rule 1: Block USB storage devices
        if self.block_usb_storage and device.device_type == "usb" and device.is_storage:
            return False, "USB storage devices are blocked by policy"

        # Rule 2: Block all Bluetooth
        if self.block_bluetooth and device.device_type == "bluetooth":
            return False, "Bluetooth devices are blocked by policy"

        # Rule 3: Blocked USB vendors (explicit deny list)
        if device.device_type == "usb" and self.blocked_usb_vendors:
            vid = device.vendor_id.upper().strip()
            for blocked in self.blocked_usb_vendors:
                if blocked.upper().strip() == vid:
                    return False, f"USB vendor {vid} is blocked by policy"

        # Rule 4: Allowed USB vendors (explicit allow list — everything else blocked)
        if device.device_type == "usb" and self.allowed_usb_vendors:
            vid = device.vendor_id.upper().strip()
            allowed_upper = [v.upper().strip() for v in self.allowed_usb_vendors]
            if vid and vid not in allowed_upper:
                return False, f"USB vendor {vid} is not in the allowed list"

        return True, ""

    def check_device_counts(
        self, devices: list[DeviceInfo]
    ) -> list[tuple[bool, str]]:
        """Check aggregate device count limits.

        Returns a list of (compliant, reason) tuples for any violated limits.
        """
        violations: list[tuple[bool, str]] = []

        usb_count = sum(1 for d in devices if d.device_type == "usb")
        bt_count = sum(1 for d in devices if d.device_type == "bluetooth")

        if usb_count > self.max_usb_devices:
            violations.append((
                False,
                f"USB device count ({usb_count}) exceeds maximum ({self.max_usb_devices})",
            ))

        if bt_count > self.max_bluetooth_devices:
            violations.append((
                False,
                f"Bluetooth device count ({bt_count}) exceeds maximum ({self.max_bluetooth_devices})",
            ))

        return violations

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to a dictionary."""
        return {
            "block_usb_storage": self.block_usb_storage,
            "max_usb_devices": self.max_usb_devices,
            "max_bluetooth_devices": self.max_bluetooth_devices,
            "allowed_usb_vendors": self.allowed_usb_vendors,
            "blocked_usb_vendors": self.blocked_usb_vendors,
            "block_bluetooth": self.block_bluetooth,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DevicePolicy:
        """Deserialize policy from a dictionary."""
        return cls(
            block_usb_storage=data.get("block_usb_storage", False),
            max_usb_devices=data.get("max_usb_devices", 20),
            max_bluetooth_devices=data.get("max_bluetooth_devices", 10),
            allowed_usb_vendors=data.get("allowed_usb_vendors", []),
            blocked_usb_vendors=data.get("blocked_usb_vendors", []),
            block_bluetooth=data.get("block_bluetooth", False),
        )
