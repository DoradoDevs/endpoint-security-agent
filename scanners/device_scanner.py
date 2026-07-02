"""
Sentinel Agent — Device Scanner

Enumerates USB and Bluetooth peripherals, detects removable storage,
checks for unknown/unauthorized devices, and enforces device policy.
"""

from __future__ import annotations

from core.config import AgentConfig, Severity
from core.telemetry import Finding
from scanners.base import BaseScanner
from scanners.device_inventory import DeviceInfo, DeviceInventory
from scanners.device_policy import DevicePolicy


# Known storage-related USB class codes and keywords
_STORAGE_KEYWORDS = frozenset({
    "mass storage",
    "disk",
    "flash drive",
    "thumb drive",
    "external hard",
    "portable drive",
    "card reader",
    "sd card",
    "usb drive",
})

# Vendor IDs commonly associated with USB storage (sample list)
_COMMON_STORAGE_VENDORS: dict[str, str] = {
    "0781": "SanDisk",
    "0930": "Toshiba",
    "058F": "Alcor Micro (card reader)",
    "13FE": "Kingston Technology",
    "090C": "Silicon Motion",
    "0951": "Kingston",
    "1F75": "Innostor",
}


class DeviceScanner(BaseScanner):
    """USB and Bluetooth device security scanner."""

    def __init__(self, config: AgentConfig) -> None:
        super().__init__(config)
        self._inventory = DeviceInventory()
        self._policy = DevicePolicy()

    @property
    def name(self) -> str:
        return "DeviceScanner"

    @property
    def description(self) -> str:
        return "USB and Bluetooth device inventory, removable storage detection, policy compliance"

    def scan(self) -> list[Finding]:
        """Execute device scan and return findings."""
        findings: list[Finding] = []

        # Enumerate all devices
        devices = self._inventory.enumerate_all()

        usb_devices = [d for d in devices if d.device_type == "usb"]
        bt_devices = [d for d in devices if d.device_type == "bluetooth"]

        # ── INFO: Device inventory ──────────────────────────────────
        findings.append(Finding(
            title="Device Inventory",
            description=(
                f"Enumerated {len(devices)} devices: "
                f"{len(usb_devices)} USB, {len(bt_devices)} Bluetooth"
            ),
            severity=Severity.INFO,
            category="Device Security",
            scanner=self.name,
            evidence={
                "total_devices": len(devices),
                "usb_count": len(usb_devices),
                "bluetooth_count": len(bt_devices),
                "devices": [d.to_dict() for d in devices],
            },
        ))

        # ── Removable storage detection ─────────────────────────────
        storage_devices = [d for d in usb_devices if d.is_storage]
        if storage_devices:
            severity = Severity.MEDIUM if len(storage_devices) <= 2 else Severity.HIGH
            findings.append(Finding(
                title="Removable USB Storage Detected",
                description=(
                    f"{len(storage_devices)} removable USB storage "
                    f"device(s) connected. Data exfiltration risk."
                ),
                severity=severity,
                category="USB Security",
                scanner=self.name,
                evidence={
                    "storage_device_count": len(storage_devices),
                    "devices": [d.to_dict() for d in storage_devices],
                },
                remediation=(
                    "Review connected USB storage devices. Consider disabling "
                    "USB mass storage via Group Policy or endpoint management. "
                    "Enable USB device logging."
                ),
            ))

        # ── Known storage vendor check ──────────────────────────────
        for device in usb_devices:
            vid = device.vendor_id.upper().strip()
            if vid in _COMMON_STORAGE_VENDORS and not device.is_storage:
                findings.append(Finding(
                    title=f"Potential Storage Device: {_COMMON_STORAGE_VENDORS[vid]}",
                    description=(
                        f"USB device from known storage vendor "
                        f"{_COMMON_STORAGE_VENDORS[vid]} (VID {vid}) detected."
                    ),
                    severity=Severity.LOW,
                    category="USB Security",
                    scanner=self.name,
                    evidence=device.to_dict(),
                    remediation="Verify the device is authorized for use on this system.",
                ))

        # ── Excessive USB device count ──────────────────────────────
        if len(usb_devices) > self._policy.max_usb_devices:
            findings.append(Finding(
                title="Excessive USB Devices Connected",
                description=(
                    f"{len(usb_devices)} USB devices connected, exceeding the "
                    f"policy maximum of {self._policy.max_usb_devices}."
                ),
                severity=Severity.MEDIUM,
                category="USB Security",
                scanner=self.name,
                evidence={
                    "usb_count": len(usb_devices),
                    "max_allowed": self._policy.max_usb_devices,
                },
                remediation="Remove unnecessary USB devices and review device policy.",
            ))

        # ── Bluetooth device checks ─────────────────────────────────
        if bt_devices:
            findings.append(Finding(
                title="Bluetooth Devices Detected",
                description=(
                    f"{len(bt_devices)} Bluetooth device(s) detected. "
                    f"Wireless connections may pose eavesdropping or "
                    f"unauthorized access risks."
                ),
                severity=Severity.LOW,
                category="Bluetooth Security",
                scanner=self.name,
                evidence={
                    "bluetooth_count": len(bt_devices),
                    "devices": [d.to_dict() for d in bt_devices],
                },
                remediation=(
                    "Review paired Bluetooth devices. Disable Bluetooth when "
                    "not in use. Ensure devices require authentication."
                ),
            ))

        if len(bt_devices) > self._policy.max_bluetooth_devices:
            findings.append(Finding(
                title="Excessive Bluetooth Devices",
                description=(
                    f"{len(bt_devices)} Bluetooth devices connected, exceeding "
                    f"the policy maximum of {self._policy.max_bluetooth_devices}."
                ),
                severity=Severity.MEDIUM,
                category="Bluetooth Security",
                scanner=self.name,
                evidence={
                    "bluetooth_count": len(bt_devices),
                    "max_allowed": self._policy.max_bluetooth_devices,
                },
                remediation="Remove unnecessary Bluetooth pairings.",
            ))

        # ── Policy compliance ───────────────────────────────────────
        policy_violations = self._check_policy(devices)
        findings.extend(policy_violations)

        return findings

    def _check_policy(self, devices: list[DeviceInfo]) -> list[Finding]:
        """Check all devices against the device policy."""
        findings: list[Finding] = []

        for device in devices:
            compliant, reason = self._policy.check_device(device)
            if not compliant:
                findings.append(Finding(
                    title=f"Device Policy Violation: {device.name}",
                    description=reason,
                    severity=Severity.HIGH,
                    category="Device Security",
                    scanner=self.name,
                    evidence={
                        "device": device.to_dict(),
                        "policy_reason": reason,
                    },
                    remediation=(
                        "Remove or disconnect the non-compliant device. "
                        "Update device policy if this device should be allowed."
                    ),
                ))

        # Check aggregate counts
        count_violations = self._policy.check_device_counts(devices)
        for compliant, reason in count_violations:
            if not compliant:
                findings.append(Finding(
                    title="Device Count Policy Violation",
                    description=reason,
                    severity=Severity.MEDIUM,
                    category="Device Security",
                    scanner=self.name,
                    evidence={"policy_reason": reason},
                    remediation="Reduce the number of connected devices.",
                ))

        return findings

    def set_policy(self, policy: DevicePolicy) -> None:
        """Update the device policy used during scanning."""
        self._policy = policy

    def set_inventory(self, inventory: DeviceInventory) -> None:
        """Override the device inventory (useful for testing)."""
        self._inventory = inventory
